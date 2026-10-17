package app

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

type devicePrincipal struct{ ID, OrganizationID string }
type deviceEndpoint func(http.ResponseWriter, *http.Request, devicePrincipal) error

func (a *App) device(fn deviceEndpoint) endpoint {
	return func(w http.ResponseWriter, r *http.Request) error {
		authorization := r.Header.Get("Authorization")
		if !strings.HasPrefix(authorization, "Bearer ") || len(authorization) != 71 {
			return &apiError{401, "device credentials required"}
		}
		var device devicePrincipal
		err := a.db.QueryRow(r.Context(), "SELECT id,organization_id FROM devices WHERE token_hash=$1 AND revoked_at IS NULL", digest(strings.TrimPrefix(authorization, "Bearer "))).Scan(&device.ID, &device.OrganizationID)
		if errors.Is(err, pgx.ErrNoRows) {
			return &apiError{401, "device credential invalid or revoked"}
		}
		if err != nil {
			return err
		}
		return fn(w, r, device)
	}
}
func collectorState(s string) bool {
	switch s {
	case "healthy", "missing", "unknown", "simulated", "stopped":
		return true
	}
	return false
}
func (a *App) heartbeat(w http.ResponseWriter, r *http.Request, device devicePrincipal) error {
	var rawInput json.RawMessage
	if err := decode(w, r, &rawInput); err != nil {
		return err
	}
	var input nativeHealth
	if err := json.Unmarshal(rawInput, &input); err != nil {
		return invalid("invalid heartbeat")
	}
	decoder := json.NewDecoder(bytes.NewReader(rawInput))
	decoder.DisallowUnknownFields()
	if input.Version == 0 || input.Version == 1 {
		var legacy struct {
			Version   int    `json:"schema_version"`
			Helper    string `json:"helper"`
			Extension string `json:"extension"`
		}
		if err := decoder.Decode(&legacy); err != nil {
			return invalid("native heartbeat requires schema version 2")
		}
	} else if err := decoder.Decode(&input); err != nil {
		return invalid("invalid native heartbeat")
	}
	if !collectorState(input.Helper) || !collectorState(input.Extension) {
		return invalid("valid helper and extension status required")
	}
	if input.Version == 2 {
		if !validHealth(input) {
			return invalid("invalid native heartbeat")
		}
		tx, err := a.db.Begin(r.Context())
		if err != nil {
			return err
		}
		defer tx.Rollback(r.Context())
		var raw []byte
		if err = tx.QueryRow(r.Context(), "SELECT loss_counters FROM devices WHERE id=$1 AND revoked_at IS NULL FOR UPDATE", device.ID).Scan(&raw); errors.Is(err, pgx.ErrNoRows) {
			return &apiError{401, "device revoked"}
		} else if err != nil {
			return err
		}
		counters := map[string]int64{}
		if err = json.Unmarshal(raw, &counters); err != nil {
			return err
		}
		previous, seen := counters[input.Epoch]
		if (seen && input.Lost < previous) || (!seen && len(counters) >= 64) {
			return &apiError{409, "loss counter epoch inconsistent; administrator recovery required"}
		}
		counters[input.Epoch] = input.Lost
		var total int64
		for _, value := range counters {
			if value > 9007199254740991-total {
				return invalid("total loss count exceeds supported range")
			}
			total += value
		}
		healthBytes, err := json.Marshal(input)
		if err != nil {
			return err
		}
		var health map[string]any
		if err = json.Unmarshal(healthBytes, &health); err != nil {
			return err
		}
		health["total_lost_events"] = total
		healthBytes, err = json.Marshal(health)
		if err != nil {
			return err
		}
		counterBytes, err := json.Marshal(counters)
		if err != nil {
			return err
		}
		if _, err = tx.Exec(r.Context(), "UPDATE devices SET last_contact=now(),helper_status=$1,extension_status=$2,health=$3,health_received_at=now(),loss_counters=$4 WHERE id=$5", input.Helper, input.Extension, healthBytes, counterBytes, device.ID); err != nil {
			return err
		}
		if err = tx.Commit(r.Context()); err != nil {
			return err
		}
		return send(w, 200, map[string]any{"status": "accepted"})
	}
	if (input.Version != 0 && input.Version != 1) || input.State != "" || input.Policy != "" || input.Epoch != "" || input.Error != "" || input.QueueEvents != 0 || input.QueueBytes != 0 || input.Lost != 0 {
		return invalid("native heartbeat requires schema version 2")
	}
	tag, err := a.db.Exec(r.Context(), "UPDATE devices SET last_contact=now(),helper_status=$1,extension_status=$2 WHERE id=$3 AND revoked_at IS NULL", input.Helper, input.Extension, device.ID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return &apiError{401, "device revoked"}
	}
	return send(w, 200, map[string]any{"status": "accepted"})
}

type Payload struct {
	GapReason   string    `json:"gap_reason,omitempty"`
	Start       time.Time `json:"start,omitempty"`
	End         time.Time `json:"end,omitempty"`
	App         string    `json:"app,omitempty"`
	Hostname    string    `json:"hostname,omitempty"`
	Service     string    `json:"service,omitempty"`
	State       string    `json:"state,omitempty"`
	StartupType string    `json:"startup_type,omitempty"`
}
type Event struct {
	ID       string    `json:"event_id"`
	Session  string    `json:"session_id"`
	Sequence int64     `json:"sequence"`
	Observed time.Time `json:"observed_at"`
	Kind     string    `json:"kind"`
	Payload  Payload   `json:"payload"`
}

var domainPattern = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?$`)

func validateEvent(event Event, now time.Time, retention int) error {
	if len(event.ID) < 1 || len(event.ID) > 128 || len(event.Session) < 1 || len(event.Session) > 128 || event.Sequence < 0 {
		return invalid("invalid event identity or sequence")
	}
	if event.Observed.IsZero() || event.Observed.After(now.Add(5*time.Minute)) || event.Observed.Before(now.AddDate(0, 0, -retention)) {
		return invalid("observation outside accepted time window")
	}
	p := event.Payload
	if event.Kind == "service" {
		if len(p.Service) < 1 || len(p.Service) > 120 || p.App != "" || p.Hostname != "" || !p.Start.IsZero() || !p.End.IsZero() {
			return invalid("invalid service payload")
		}
		switch p.State {
		case "running", "stopped", "paused", "start_pending", "stop_pending", "continue_pending", "pause_pending", "unknown":
		default:
			return invalid("unsupported service state")
		}
		switch p.StartupType {
		case "automatic", "manual", "disabled", "unknown":
		default:
			return invalid("unsupported startup type")
		}
		return nil
	}
	if p.Start.IsZero() || !p.End.After(p.Start) || p.End.Sub(p.Start) > 24*time.Hour || p.End.After(event.Observed) || p.Start.Before(now.AddDate(0, 0, -retention)) || p.Service != "" || p.State != "" || p.StartupType != "" {
		return invalid("invalid interval payload")
	}
	switch event.Kind {
	case "application":
		if len(p.App) < 1 || len(p.App) > 120 || strings.ContainsAny(p.App, "\\/:\x00") || p.Hostname != "" {
			return invalid("application basename required")
		}
	case "browser":
		if !domainPattern.MatchString(p.Hostname) || strings.Contains(p.Hostname, "..") || p.App != "" {
			return invalid("normalized hostname only; full URLs are prohibited")
		}
	case "idle", "locked", "gap":
		if p.App != "" || p.Hostname != "" {
			return invalid("unexpected activity details")
		}
	default:
		return invalid("unsupported event kind")
	}
	return nil
}
func SplitDays(start, end time.Time, location *time.Location) map[string]int64 {
	result := map[string]int64{}
	for start.Before(end) {
		local := start.In(location)
		year, month, day := local.Date()
		next := time.Date(year, month, day+1, 0, 0, 0, 0, location)
		stop := end
		if next.Before(stop) {
			stop = next
		}
		result[local.Format("2006-01-02")] += int64(stop.Sub(start) / time.Second)
		start = stop
	}
	return result
}
func (a *App) ingest(w http.ResponseWriter, r *http.Request, device devicePrincipal) error {
	var input struct {
		Version int     `json:"schema_version"`
		Events  []Event `json:"events"`
	}
	if err := decode(w, r, &input); err != nil {
		return err
	}
	if (input.Version != 1 && input.Version != 2) || len(input.Events) < 1 || len(input.Events) > 500 {
		return invalid("schema version 1 or 2 and 1 to 500 events required")
	}
	tx, err := a.db.Begin(r.Context())
	if err != nil {
		return err
	}
	defer tx.Rollback(r.Context())
	var revoked *time.Time
	var zone string
	var days int
	var watermark time.Time
	// Serialize device ingestion and revocation to protect overlap checks and acknowledgements.
	if err = tx.QueryRow(r.Context(), "SELECT revoked_at FROM devices WHERE id=$1 FOR UPDATE", device.ID).Scan(&revoked); err != nil {
		return err
	}
	if revoked != nil {
		return &apiError{401, "device revoked"}
	}
	if err = tx.QueryRow(r.Context(), "SELECT timezone,raw_retention_days,ingest_not_before FROM organizations WHERE id=$1 FOR SHARE", device.OrganizationID).Scan(&zone, &days, &watermark); err != nil {
		return err
	}
	location, err := time.LoadLocation(zone)
	if err != nil {
		return err
	}
	accepted := []string{}
	now := time.Now().UTC()
	for _, event := range input.Events {
		if event.Payload.GapReason != "" && (input.Version != 2 || event.Kind != "gap" || !allowed(event.Payload.GapReason, "helper_missing", "suspended", "logged_out", "unsupported_session", "clock_discontinuity", "queue_overflow", "local_storage_failure", "process_unavailable", "policy_expired")) {
			return invalid("unsupported gap reason or event schema")
		}
		if err = validateEvent(event, now, days); err != nil {
			return err
		}
		if event.Observed.Before(watermark) || (!event.Payload.Start.IsZero() && event.Payload.Start.Before(watermark)) {
			return invalid("observation predates the retained raw-data watermark")
		}
		canonical, _ := json.Marshal(event)
		hash := digest(string(canonical))
		var existing string
		var existingVersion int
		err = tx.QueryRow(r.Context(), "SELECT content_hash,wire_version FROM events WHERE device_id=$1 AND event_id=$2", device.ID, event.ID).Scan(&existing, &existingVersion)
		if err == nil {
			if existing != hash || existingVersion != input.Version {
				return &apiError{409, "event ID has conflicting content"}
			}
			accepted = append(accepted, event.ID)
			continue
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		p := event.Payload
		if event.Kind != "service" && event.Kind != "browser" {
			var overlaps bool
			err = tx.QueryRow(r.Context(), "SELECT EXISTS(SELECT 1 FROM events WHERE device_id=$1 AND kind IN ('application','idle','locked','gap') AND starts_at<$3 AND ends_at>$2)", device.ID, p.Start, p.End).Scan(&overlaps)
			if err != nil {
				return err
			}
			if overlaps {
				return &apiError{409, "activity intervals overlap"}
			}
		}
		if event.Kind == "browser" {
			var overlaps bool
			err = tx.QueryRow(r.Context(), "SELECT EXISTS(SELECT 1 FROM events WHERE device_id=$1 AND kind='browser' AND starts_at<$3 AND ends_at>$2)", device.ID, p.Start, p.End).Scan(&overlaps)
			if err != nil {
				return err
			}
			if overlaps {
				return &apiError{409, "browser intervals overlap"}
			}
		}
		payload, _ := json.Marshal(p)
		var start, end any
		if event.Kind != "service" {
			start, end = p.Start, p.End
		}
		if _, err = tx.Exec(r.Context(), "INSERT INTO events(device_id,event_id,session_id,sequence,observed_at,kind,starts_at,ends_at,payload,content_hash,wire_version) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)", device.ID, event.ID, event.Session, event.Sequence, event.Observed, event.Kind, start, end, payload, hash, input.Version); err != nil {
			return err
		}
		if event.Kind != "service" {
			label := p.App
			if event.Kind == "browser" {
				label = p.Hostname
			}
			for day, seconds := range SplitDays(p.Start, p.End, location) {
				_, err = tx.Exec(r.Context(), "INSERT INTO daily_summaries(device_id,day,timezone,kind,label,seconds) VALUES($1,$2::date,$3,$4,$5,$6) ON CONFLICT(device_id,day,timezone,kind,label) DO UPDATE SET seconds=daily_summaries.seconds+excluded.seconds", device.ID, day, zone, event.Kind, label, seconds)
				if err != nil {
					return err
				}
			}
		}
		accepted = append(accepted, event.ID)
	}
	if _, err = tx.Exec(r.Context(), "UPDATE devices SET last_contact=now() WHERE id=$1", device.ID); err != nil {
		return err
	}
	if err = tx.Commit(r.Context()); err != nil {
		return err
	}
	return send(w, 200, map[string]any{"accepted_event_ids": accepted})
}
func (a *App) revokeDevice(w http.ResponseWriter, r *http.Request, user principal) error {
	tx, err := a.db.Begin(r.Context())
	if err != nil {
		return err
	}
	defer tx.Rollback(r.Context())
	tag, err := tx.Exec(r.Context(), "UPDATE devices SET revoked_at=coalesce(revoked_at,now()) WHERE id=$1 AND organization_id=$2", r.PathValue("id"), user.OrganizationID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return missing()
	}
	if err = audit(r.Context(), tx, user.OrganizationID, user.ID, "device_revoked", r.PathValue("id")); err != nil {
		return err
	}
	if err = tx.Commit(r.Context()); err != nil {
		return err
	}
	return send(w, 200, map[string]any{"status": "revoked"})
}
