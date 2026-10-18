package agent

import (
	"errors"
	"fmt"
	"strings"
)

type Status struct {
	State       string
	Helper      string
	Policy      string
	QueueEvents int64
	LostEvents  int64
	LastError   string
}

func (status Status) Notice() (string, error) {
	switch status.State {
	case "collecting", "idle", "locked", "outside_schedule", "offline", "helper_missing", "policy_unavailable", "revoked", "error", "unsupported_session", "suspended", "logged_out":
	default:
		return "", errors.New("invalid collection status")
	}
	return fmt.Sprintf("CherrySecurity is managed by your organization. It records applications by executable name and Windows services during the configured schedule. It does not collect window titles, document contents, screenshots, clipboard data, audio, video, or keystrokes.\r\n\r\nStatus: %s\r\nHelper: %s\r\nPolicy: %s\r\nQueued events: %d\r\nLost events: %d", strings.ReplaceAll(status.State, "_", " "), status.Helper, status.Policy, status.QueueEvents, status.LostEvents), nil
}
