package agent

import (
	"context"
	"errors"
	"fmt"
	"net"
	"runtime"
	"strings"
	"time"
	"unsafe"

	"github.com/Microsoft/go-winio"
	"golang.org/x/sys/windows"
)

const helperPipe = `\\.\pipe\CherrySecurity-session`
const enrollmentPipe = `\\.\pipe\CherrySecurity-enrollment`
const pipeClientRights = windows.FILE_READ_DATA | windows.FILE_WRITE_DATA | windows.FILE_READ_ATTRIBUTES | windows.SYNCHRONIZE

type SessionBinding struct {
	UserSID, LogonSID, ServiceSID, ServicePath string
	SessionID                                  uint32
}

func helperPipeACL(binding SessionBinding) (string, error) {
	for _, value := range []string{binding.UserSID, binding.ServiceSID} {
		sid, err := windows.StringToSid(value)
		if err != nil || sid.String() != value {
			return "", errors.New("invalid pipe identity")
		}
	}
	if !(strings.HasPrefix(binding.UserSID, "S-1-5-21-") || strings.HasPrefix(binding.UserSID, "S-1-12-1-")) || !strings.HasPrefix(binding.ServiceSID, "S-1-5-80-") {
		return "", errors.New("invalid session/service SID")
	}
	return fmt.Sprintf("D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;%s)(A;;0x100083;;;%s)", binding.ServiceSID, binding.UserSID), nil
}

func pipeHandle(connection net.Conn) (windows.Handle, error) {
	handle, ok := connection.(interface{ Fd() uintptr })
	if !ok {
		return 0, errors.New("pipe handle unavailable")
	}
	return windows.Handle(handle.Fd()), nil
}

func inspectPipeClient(connection net.Conn, check func(windows.Token) error) error {
	handle, err := pipeHandle(connection)
	if err != nil {
		return err
	}
	runtime.LockOSThread()
	impersonate := windows.NewLazySystemDLL("advapi32.dll").NewProc("ImpersonateNamedPipeClient")
	result, _, callErr := impersonate.Call(uintptr(handle))
	if result == 0 {
		runtime.UnlockOSThread()
		return callErr
	}
	defer func() {
		if err := windows.RevertToSelf(); err != nil {
			panic("could not revert pipe identity")
		}
		runtime.UnlockOSThread()
	}()
	var clientToken windows.Token
	if err = windows.OpenThreadToken(windows.CurrentThread(), windows.TOKEN_QUERY, true, &clientToken); err != nil {
		return err
	}
	defer clientToken.Close()
	return check(clientToken)
}

func tokenSession(identity windows.Token) (uint32, error) {
	var session, length uint32
	err := windows.GetTokenInformation(identity, windows.TokenSessionId, (*byte)(unsafe.Pointer(&session)), 4, &length)
	return session, err
}
func tokenLogonSID(identity windows.Token) (string, error) {
	groups, err := identity.GetTokenGroups()
	if err != nil {
		return "", err
	}
	for _, group := range groups.AllGroups() {
		if group.Attributes&windows.SE_GROUP_LOGON_ID == windows.SE_GROUP_LOGON_ID {
			return group.Sid.String(), nil
		}
	}
	return "", errors.New("interactive logon identity unavailable")
}
func verifyClientToken(identity windows.Token, binding SessionBinding) error {
	user, err := identity.GetTokenUser()
	if err != nil {
		return err
	}
	session, err := tokenSession(identity)
	if err != nil {
		return err
	}
	logon, err := tokenLogonSID(identity)
	if err != nil {
		return err
	}
	if user.User.Sid.String() != binding.UserSID || (binding.SessionID != ^uint32(0) && session != binding.SessionID) || session != windows.WTSGetActiveConsoleSessionId() || !strings.HasPrefix(logon, "S-1-5-5-") || (binding.LogonSID != "" && logon != binding.LogonSID) {
		return errors.New("helper identity rejected")
	}
	return nil
}

func verifyPipeServer(connection net.Conn, binding SessionBinding) error {
	handle, err := pipeHandle(connection)
	if err != nil {
		return err
	}
	var pid uint32
	if err = windows.GetNamedPipeServerProcessId(handle, &pid); err != nil {
		return err
	}
	manager, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT)
	if err != nil {
		return err
	}
	defer windows.CloseServiceHandle(manager)
	serviceName, err := windows.UTF16PtrFromString("CherrySecurityAgent")
	if err != nil {
		return err
	}
	service, err := windows.OpenService(manager, serviceName, windows.SERVICE_QUERY_STATUS)
	if err != nil {
		return err
	}
	defer windows.CloseServiceHandle(service)
	var status windows.SERVICE_STATUS_PROCESS
	var needed uint32
	if err = windows.QueryServiceStatusEx(service, windows.SC_STATUS_PROCESS_INFO, (*byte)(unsafe.Pointer(&status)), uint32(unsafe.Sizeof(status)), &needed); err != nil {
		return err
	}
	if status.ProcessId != pid || pid == 0 || status.CurrentState != windows.SERVICE_RUNNING {
		return errors.New("unexpected pipe server")
	}
	// Standard users cannot open a LocalService process, so the server is bound through the SCM instead:
	// only the SCM starts this PID, and only administrators can change the service's binary or account.
	return nil
}

func ConnectHelperPipe(ctx context.Context, binding SessionBinding) (net.Conn, error) {
	connection, err := winio.DialPipeAccessImpLevel(ctx, helperPipe, uint32(pipeClientRights), winio.PipeImpLevelIdentification)
	if err != nil {
		return nil, err
	}
	if err = verifyPipeServer(connection, binding); err != nil {
		connection.Close()
		return nil, err
	}
	return connection, nil
}

func ListenHelperPipe(ctx context.Context, binding SessionBinding, handler func(HelperMessage) (HelperReply, error)) error {
	return listenHelperPipe(ctx, binding, handler, nil)
}

func listenHelperPipe(ctx context.Context, binding SessionBinding, handler func(HelperMessage) (HelperReply, error), disconnected func()) error {
	descriptor, err := helperPipeACL(binding)
	if err != nil {
		return err
	}
	listener, err := winio.ListenPipe(helperPipe, &winio.PipeConfig{SecurityDescriptor: descriptor, InputBufferSize: maxFrame, OutputBufferSize: maxFrame})
	if err != nil {
		return err
	}
	defer listener.Close()
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			listener.Close()
		case <-done:
		}
	}()
	for {
		connection, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return err
		}
		// One selected session: serialize connections and bound each idle read.
		connected := serveHelperConnection(connection, binding, handler)
		connection.Close()
		if connected && disconnected != nil {
			disconnected()
		}
	}
}
func serveHelperConnection(connection net.Conn, binding SessionBinding, handler func(HelperMessage) (HelperReply, error)) bool {
	nonce := token()
	var previous uint64
	var previousBytes string
	var previousReply HelperReply
	connection.SetDeadline(time.Now().Add(10 * time.Second))
	var hello HelperMessage
	if ReadFrame(connection, &hello) != nil || hello.Version != 1 || hello.Kind != "hello" || hello.EnrollmentKey != "" || hello.MessageID != "" || hello.HelperInstance != "" || len(hello.Samples) != 0 {
		return false
	}
	if inspectPipeClient(connection, func(identity windows.Token) error { return verifyClientToken(identity, binding) }) != nil {
		return false
	}
	reply, err := handler(hello)
	if err != nil {
		return false
	}
	reply.Version = 1
	reply.Nonce = nonce
	reply.State = "connected"
	if WriteFrame(connection, reply) != nil {
		return true
	}
	for {
		connection.SetDeadline(time.Now().Add(10 * time.Second))
		var message HelperMessage
		if ReadFrame(connection, &message) != nil {
			return true
		}
		if message.Version != 1 || message.Nonce != nonce || message.Sequence == 0 || !validToken(message.MessageID) || !validToken(message.HelperInstance) || message.EnrollmentKey != "" || len(message.Samples) > 5 || (message.Kind != "samples" && message.Kind != "status") || (message.Kind == "samples" && len(message.Samples) == 0) || (message.Kind == "status" && len(message.Samples) != 0) {
			return true
		}
		encoded, err := frameDigest(message)
		if err != nil {
			return true
		}
		if message.Sequence == previous {
			if encoded != previousBytes {
				return true
			}
			if WriteFrame(connection, previousReply) != nil {
				return true
			}
			continue
		}
		if previous != 0 && message.Sequence != previous+1 {
			return true
		}
		reply, err := handler(message)
		if err != nil {
			return true
		}
		reply.Version = 1
		reply.Nonce = nonce
		reply.Sequence = message.Sequence
		previous = message.Sequence
		previousBytes = encoded
		previousReply = reply
		if WriteFrame(connection, reply) != nil {
			return true
		}
	}
}

// enrollmentPipeACL admits SYSTEM, administrators and the service itself; go-winio must reopen
// the pipe for each new instance, so a DACL without the server's own SID fails Accept with access denied.
func enrollmentPipeACL(serverSID string) (string, error) {
	sid, err := windows.StringToSid(serverSID)
	if err != nil || sid.String() != serverSID {
		return "", errors.New("invalid enrollment server identity")
	}
	return "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;" + serverSID + ")", nil
}

func ServeEnrollment(ctx context.Context, serverSID string, enroll func(context.Context, []byte) error) error {
	descriptor, err := enrollmentPipeACL(serverSID)
	if err != nil {
		return err
	}
	listener, err := winio.ListenPipe(enrollmentPipe, &winio.PipeConfig{SecurityDescriptor: descriptor, InputBufferSize: 4096, OutputBufferSize: 4096})
	if err != nil {
		return err
	}
	defer listener.Close()
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			listener.Close()
		case <-done:
		}
	}()
	for {
		connection, err := listener.Accept()
		if err != nil {
			return err
		}
		connection.SetDeadline(time.Now().Add(10 * time.Second))
		var message HelperMessage
		readErr := ReadFrame(connection, &message)
		if readErr == nil {
			readErr = inspectPipeClient(connection, func(identity windows.Token) error {
				admin, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
				if err != nil {
					return err
				}
				member, err := identity.IsMember(admin)
				if err != nil {
					return err
				}
				if !member {
					return errors.New("administrator required")
				}
				return nil
			})
		}
		if readErr == nil && message.Version == 1 && message.Kind == "enroll" && validToken(message.EnrollmentKey) {
			key := []byte(message.EnrollmentKey)
			readErr = enroll(ctx, key)
			clear(key)
			message.EnrollmentKey = ""
		} else {
			readErr = errors.New("invalid enrollment request")
		}
		reply := HelperReply{Version: 1, State: "enrolled"}
		if readErr != nil {
			reply.State = "error"
			reply.Error = "enrollment_failed"
		}
		_ = WriteFrame(connection, reply)
		connection.Close()
	}
}

func RequestEnrollment(ctx context.Context, binding SessionBinding, enrollmentKey []byte) error {
	if !validToken(string(enrollmentKey)) {
		return errors.New("invalid enrollment key")
	}
	connection, err := winio.DialPipeAccessImpLevel(ctx, enrollmentPipe, uint32(pipeClientRights), winio.PipeImpLevelIdentification)
	if err != nil {
		return err
	}
	defer connection.Close()
	if err = verifyPipeServer(connection, binding); err != nil {
		return err
	}
	connection.SetDeadline(time.Now().Add(10 * time.Second))
	message := HelperMessage{Version: 1, Kind: "enroll", EnrollmentKey: string(enrollmentKey)}
	if err = WriteFrame(connection, message); err != nil {
		return err
	}
	message.EnrollmentKey = ""
	var reply HelperReply
	if err = ReadFrame(connection, &reply); err != nil {
		return err
	}
	if reply.Version != 1 || reply.State != "enrolled" || reply.Error != "" {
		return errors.New("enrollment rejected")
	}
	return nil
}
