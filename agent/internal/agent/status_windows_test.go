package agent

import (
	"strings"
	"testing"
)

func TestStatusNoticeContainsDisclosureAndNoSecrets(t *testing.T) {
	status := Status{State: "collecting", Helper: "healthy", Policy: "current", QueueEvents: 4}
	notice, err := status.Notice()
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{"CherrySecurity", "applications", "Windows services", "does not collect", "window titles", "screenshots", "keystrokes"} {
		if !strings.Contains(notice, required) {
			t.Fatalf("notice does not disclose %q: %s", required, notice)
		}
	}
	if strings.Contains(notice, "Bearer ") || strings.Contains(notice, "device_token") {
		t.Fatal("notice exposes credentials")
	}
	if _, err := (Status{State: "invented"}).Notice(); err == nil {
		t.Fatal("unknown status accepted")
	}
}
