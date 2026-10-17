package agent

import (
	"context"
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
	if strings.Contains(descriptor, ";;;WD)") || strings.Contains(descriptor, ";;;AU)") || !strings.Contains(descriptor, binding.LogonSID) {
		t.Fatal("pipe ACL is not session scoped")
	}
	binding.LogonSID = "S-1-5-5-1-2)(A;;GA;;;WD)"
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
	logon, err := tokenLogonSID(identity)
	if err != nil {
		t.Fatal(err)
	}
	binding := SessionBinding{UserSID: user.User.Sid.String(), LogonSID: logon, SessionID: session, ServiceSID: "S-1-5-80-1-2-3-4-5"}
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
