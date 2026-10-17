package app

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"
)

func (a *App) agentPolicy(w http.ResponseWriter, r *http.Request, device devicePrincipal) error {
	var zone string
	var idle, retention int
	var schedule json.RawMessage
	var floor time.Time
	err := a.db.QueryRow(r.Context(), "SELECT timezone,idle_seconds,raw_retention_days,collection_schedule,ingest_not_before FROM organizations WHERE id=$1", device.OrganizationID).Scan(&zone, &idle, &retention, &schedule, &floor)
	if err != nil {
		return err
	}
	// Canonical map encoding keeps version independent of clock, JSONB formatting, and cleanup.
	var normalized Schedule
	if err = json.Unmarshal(schedule, &normalized); err != nil {
		return err
	}
	fields := map[string]any{"timezone": zone, "idle_seconds": idle, "raw_retention_days": retention, "collection_schedule": normalized, "upload_seconds": 60, "valid_for_seconds": 86400}
	canonical, err := json.Marshal(fields)
	if err != nil {
		return err
	}
	fields["policy_version"] = digest(string(canonical))
	fields["schema_version"] = 1
	fields["server_time"] = time.Now().UTC()
	fields["ingest_not_before"] = floor
	return send(w, 200, fields)
}

func (a *App) assignEmployee(w http.ResponseWriter, r *http.Request, user principal) error {
	var input struct {
		Employee string `json:"employee_id"`
	}
	if err := decode(w, r, &input); err != nil {
		return err
	}
	input.Employee = strings.TrimSpace(input.Employee)
	if len(input.Employee) > 120 || strings.ContainsAny(input.Employee, "\x00\r\n") {
		return invalid("employee identifier must be at most 120 bytes without control lines")
	}
	tx, err := a.db.Begin(r.Context())
	if err != nil {
		return err
	}
	defer tx.Rollback(r.Context())
	tag, err := tx.Exec(r.Context(), "UPDATE devices SET employee_id=$1 WHERE id=$2 AND organization_id=$3", input.Employee, r.PathValue("id"), user.OrganizationID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return missing()
	}
	if err = audit(r.Context(), tx, user.OrganizationID, user.ID, "device_employee_assigned", r.PathValue("id")); err != nil {
		return err
	}
	if err = tx.Commit(r.Context()); err != nil {
		return err
	}
	return send(w, 200, map[string]any{"status": "saved"})
}

type nativeHealth struct {
	Version     int    `json:"schema_version"`
	Helper      string `json:"helper"`
	Extension   string `json:"extension"`
	State       string `json:"collection_state,omitempty"`
	Policy      string `json:"policy_version,omitempty"`
	QueueEvents int64  `json:"queue_events"`
	QueueBytes  int64  `json:"queue_bytes"`
	Lost        int64  `json:"lost_events"`
	Epoch       string `json:"loss_epoch,omitempty"`
	Error       string `json:"last_error,omitempty"`
}

func allowed(value string, choices ...string) bool {
	for _, choice := range choices {
		if value == choice {
			return true
		}
	}
	return false
}

func validHealth(h nativeHealth) bool {
	const maxSafeInteger = 9007199254740991
	return collectorState(h.Helper) && collectorState(h.Extension) && h.Version == 2 &&
		allowed(h.State, "collecting", "idle", "locked", "outside_schedule", "offline", "helper_missing", "policy_unavailable", "revoked", "error", "unsupported_session", "suspended", "logged_out") &&
		allowed(h.Error, "none", "tls", "network", "storage", "integrity", "clock", "policy", "helper", "inventory", "credential") &&
		len(h.Policy) <= 128 && len(h.Epoch) > 0 && len(h.Epoch) <= 128 && h.QueueEvents >= 0 && h.QueueEvents <= maxSafeInteger && h.QueueBytes >= 0 && h.QueueBytes <= 50*1024*1024 && h.Lost >= 0 && h.Lost <= maxSafeInteger
}
