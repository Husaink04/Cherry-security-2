package agent

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/Microsoft/go-winio"
	"golang.org/x/sys/windows"
)

func TestPipeACLRejectsUntrustedIdentity(t *testing.T) {
	binding := SessionBinding{UserSID: "S-1-5-21-1-2-3-1001", LogonSID: "S-1-5-5-1-2", SessionID: 1, ServiceSID: "S-1-5-80-1-2-3-4-5"}
	descriptor, err := helperPipeACL(binding)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(descriptor, ";;;WD)") || strings.Contains(descriptor, ";;;AU)") || !strings.Contains(descriptor, binding.UserSID) || strings.Contains(descriptor, binding.LogonSID) {
		t.Fatal("pipe ACL is not selected-user scoped")
	}
	binding.UserSID = "S-1-5-21-1-2-3-1001)(A;;GA;;;WD)"
	if _, err = helperPipeACL(binding); err == nil {
		t.Fatal("invalid SID injection accepted")
	}
}

func TestCurrentUserNamedPipeAuthentication(t *testing.T) {
	identity := windows.GetCurrentProcessToken()
	user, err := identity.GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	session, err := tokenSession(identity)
	if err != nil {
		t.Fatal(err)
	}
	binding := SessionBinding{UserSID: user.User.Sid.String(), SessionID: session, ServiceSID: "S-1-5-80-1-2-3-4-5"}
	descriptor, err := helperPipeACL(binding)
	if err != nil {
		t.Fatal(err)
	}
	name := `\\.\pipe\CherrySecurity-test-` + token()
	// The test listener runs as this user; production grants full access to the service SID.
	listener, err := winio.ListenPipe(name, &winio.PipeConfig{SecurityDescriptor: descriptor + "(A;;GA;;;" + binding.UserSID + ")", InputBufferSize: maxFrame, OutputBufferSize: maxFrame})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	accepted := make(chan error, 1)
	go func() {
		connection, err := listener.Accept()
		if err != nil {
			accepted <- err
			return
		}
		defer connection.Close()
		connection.SetDeadline(time.Now().Add(5 * time.Second))
		var message HelperMessage
		if err = ReadFrame(connection, &message); err == nil {
			err = inspectPipeClient(connection, func(token windows.Token) error { return verifyClientToken(token, binding) })
		}
		if err == nil {
			err = WriteFrame(connection, HelperReply{Version: 1, State: "connected"})
		}
		accepted <- err
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	connection, err := winio.DialPipeAccessImpLevel(ctx, name, uint32(pipeClientRights), winio.PipeImpLevelIdentification)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	connection.SetDeadline(time.Now().Add(5 * time.Second))
	if err = WriteFrame(connection, HelperMessage{Version: 1, Kind: "hello"}); err != nil {
		t.Fatal(err)
	}
	var reply HelperReply
	if err = ReadFrame(connection, &reply); err != nil {
		t.Fatal(err)
	}
	if reply.State != "connected" {
		t.Fatalf("unexpected reply: %q", reply.State)
	}
	select {
	case err = <-accepted:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal("pipe authentication timed out")
	}
}

func TestHelperRejectsPipeServerThatIsNotTheService(t *testing.T) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	// A squatting process that creates the pipe first must not pass for the SCM-started service.
	name := `\\.\pipe\CherrySecurity-session-test-` + token()
	listener, err := winio.ListenPipe(name, &winio.PipeConfig{SecurityDescriptor: "D:P(A;;GA;;;" + user.User.Sid.String() + ")"})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		if connection, acceptErr := listener.Accept(); acceptErr == nil {
			defer connection.Close()
			time.Sleep(time.Second)
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	connection, err := winio.DialPipeContext(ctx, name)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	err = verifyPipeServer(connection, SessionBinding{UserSID: user.User.Sid.String(), ServiceSID: "S-1-5-80-1-2-3-4-5"})
	if err == nil {
		t.Fatal("a pipe served by a non-service process was accepted")
	}
	// Where the real service is installed the PID comparison is what rejects; elsewhere the service lookup fails.
	if !strings.Contains(err.Error(), "unexpected pipe server") && !errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
		t.Fatalf("rejected for an unexpected reason: %v", err)
	}
}

func TestEnrollmentPipeAdmitsItsOwnServer(t *testing.T) {
	if _, err := enrollmentPipeACL("not-a-sid"); err == nil {
		t.Fatal("malformed server identity accepted")
	}
	server := windows.GetCurrentProcessToken()
	user, err := server.GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	descriptor, err := enrollmentPipeACL(user.User.Sid.String())
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{"D:P", "(A;;GA;;;SY)", "(A;;GA;;;BA)", "(A;;GA;;;" + user.User.Sid.String() + ")"} {
		if !strings.Contains(descriptor, required) {
			t.Fatalf("enrollment pipe DACL missing %q", required)
		}
	}
	// A DACL without the server's own SID made Accept fail with access denied, stopping the installed service.
	name := `\\.\pipe\CherrySecurity-enrollment-test-` + token()
	listener, err := winio.ListenPipe(name, &winio.PipeConfig{SecurityDescriptor: descriptor})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	accepted := make(chan error, 1)
	go func() {
		connection, acceptErr := listener.Accept()
		if acceptErr == nil {
			connection.Close()
		}
		accepted <- acceptErr
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	client, err := winio.DialPipeContext(ctx, name)
	if err != nil {
		t.Fatalf("server identity could not connect to its own pipe: %v", err)
	}
	client.Close()
	select {
	case err = <-accepted:
		if err != nil {
			t.Fatalf("enrollment listener failed to accept: %v", err)
		}
	case <-ctx.Done():
		t.Fatal("enrollment listener accept timed out")
	}
}
