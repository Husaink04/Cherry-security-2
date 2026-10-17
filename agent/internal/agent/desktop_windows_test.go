package agent

import (
	"testing"
	"time"
)

func TestDesktopBoundariesAndNotice(t *testing.T) {
	at := time.Date(2026, 10, 17, 9, 0, 0, 0, time.UTC)
	cases := []struct {
		name               string
		input              desktopReading
		wantState, wantApp string
	}{
		{"foreground", desktopReading{activeSession: true, unlocked: true, idle: 3 * time.Second, application: "editor.exe"}, "active", "editor.exe"},
		{"other session", desktopReading{activeSession: false, unlocked: true, application: "secret.exe"}, "unsupported_session", ""},
		{"locked", desktopReading{activeSession: true, unlocked: false, application: "secret.exe"}, "locked", ""},
		{"protected process", desktopReading{activeSession: true, unlocked: true}, "process_unavailable", ""},
		{"lock query failed", desktopReading{activeSession: true, unknown: true, application: "secret.exe"}, "process_unavailable", ""},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			sample := classifyDesktop(test.input, at, 42*time.Second, "console-1")
			if sample.State != test.wantState || sample.App != test.wantApp {
				t.Fatalf("classified %+v", sample)
			}
		})
	}
}
