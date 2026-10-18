package app

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func jsonRows(ctx context.Context, tx pgx.Tx, query string, args ...any) ([]any, error) {
	rows, err := tx.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []any{}
	for rows.Next() {
		var raw []byte
		if err = rows.Scan(&raw); err != nil {
			return nil, err
		}
		var item map[string]any
		if err = json.Unmarshal(raw, &item); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

const deviceJSON = `jsonb_build_object('id',d.id,'hostname',d.hostname,'employee_id',d.employee_id,'os',d.os,'agent_version',d.agent_version,'simulated',d.simulated,'created_at',d.created_at,'last_contact',d.last_contact,'revoked_at',d.revoked_at,'helper_status',d.helper_status,'extension_status',d.extension_status,'health',d.health,'health_received_at',d.health_received_at,'connectivity',CASE WHEN d.revoked_at IS NOT NULL THEN 'revoked' WHEN d.last_contact IS NULL THEN 'never_seen' WHEN d.last_contact<=now()-interval '5 minutes' THEN 'offline' WHEN d.last_contact<=now()-interval '3 minutes' THEN 'stale' ELSE 'online' END)`

func (a *App) devices(w http.ResponseWriter, r *http.Request, user principal) error {
	var items []any
	err := inScope(r.Context(), a.db, user.scope(), func(tx pgx.Tx) (err error) {
		items, err = jsonRows(r.Context(), tx, "SELECT "+deviceJSON+" FROM devices d WHERE d.organization_id=$1 ORDER BY d.created_at DESC LIMIT 100", user.OrganizationID)
		return err
	})
	if err != nil {
		return err
	}
	return send(w, 200, map[string]any{"devices": items, "limit": 100, "observed_at": time.Now().UTC()})
}
func ownsDevice(ctx context.Context, tx pgx.Tx, user principal, id string) error {
	var exists bool
	if err := tx.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM devices WHERE id=$1 AND organization_id=$2)", id, user.OrganizationID).Scan(&exists); err != nil {
		return err
	}
	if !exists {
		return missing()
	}
	return nil
}
func (a *App) deviceDetail(w http.ResponseWriter, r *http.Request, user principal) error {
	var items, timeline []any
	var gaps int64
	err := inScope(r.Context(), a.db, user.scope(), func(tx pgx.Tx) (err error) {
		if items, err = jsonRows(r.Context(), tx, "SELECT "+deviceJSON+" FROM devices d WHERE d.id=$1 AND d.organization_id=$2", r.PathValue("id"), user.OrganizationID); err != nil {
			return err
		}
		if len(items) == 0 {
			return missing()
		}
		if timeline, err = jsonRows(r.Context(), tx, "SELECT jsonb_build_object('event_id',e.event_id,'kind',e.kind,'observed_at',e.observed_at,'payload',e.payload) FROM events e JOIN devices d ON d.id=e.device_id WHERE e.device_id=$1 AND d.organization_id=$2 ORDER BY e.observed_at DESC,e.event_id LIMIT 100", r.PathValue("id"), user.OrganizationID); err != nil {
			return err
		}
		// Scope every query to the tenant itself rather than relying on the earlier existence check.
		return tx.QueryRow(r.Context(), `SELECT count(*) FROM (SELECT e.sequence,lag(e.sequence) OVER (PARTITION BY e.session_id ORDER BY e.sequence,e.event_id) AS previous FROM events e JOIN devices d ON d.id=e.device_id WHERE e.device_id=$1 AND d.organization_id=$2) ordered WHERE sequence>previous+1`, r.PathValue("id"), user.OrganizationID).Scan(&gaps)
	})
	if err != nil {
		return err
	}
	return send(w, 200, map[string]any{"device": items[0], "timeline": timeline, "timeline_limit": 100, "coverage": "partial_observations", "sequence_gap_count": gaps})
}
func (a *App) services(w http.ResponseWriter, r *http.Request, user principal) error {
	var items []any
	err := inScope(r.Context(), a.db, user.scope(), func(tx pgx.Tx) (err error) {
		if err = ownsDevice(r.Context(), tx, user, r.PathValue("id")); err != nil {
			return err
		}
		items, err = jsonRows(r.Context(), tx, `SELECT jsonb_build_object('service',service,'state',payload->>'state','startup_type',payload->>'startup_type','observed_at',observed_at) FROM (SELECT DISTINCT ON (e.payload->>'service') e.payload->>'service' AS service,e.payload,e.observed_at FROM events e JOIN devices d ON d.id=e.device_id WHERE e.device_id=$1 AND d.organization_id=$2 AND e.kind='service' ORDER BY e.payload->>'service',e.observed_at DESC,e.sequence DESC,e.event_id DESC) latest ORDER BY service LIMIT 500`, r.PathValue("id"), user.OrganizationID)
		return err
	})
	if err != nil {
		return err
	}
	return send(w, 200, map[string]any{"services": items, "coverage": "observed_services_only"})
}
func (a *App) daily(w http.ResponseWriter, r *http.Request, user principal) error {
	date := r.URL.Query().Get("date")
	if _, err := time.Parse("2006-01-02", date); err != nil {
		return invalid("date must use YYYY-MM-DD")
	}
	device := r.URL.Query().Get("device_id")
	var zone string
	var items []any
	var rowCount, applicationSeconds, browserSeconds, idleSeconds, lockedSeconds, gapSeconds int64
	err := inScope(r.Context(), a.db, user.scope(), func(tx pgx.Tx) (err error) {
		if device != "" {
			if err = ownsDevice(r.Context(), tx, user, device); err != nil {
				return err
			}
		}
		if err = tx.QueryRow(r.Context(), "SELECT timezone FROM organizations WHERE id=$1", user.OrganizationID).Scan(&zone); err != nil {
			return err
		}
		if items, err = jsonRows(r.Context(), tx, `SELECT jsonb_build_object('device_id',d.id,'hostname',d.hostname,'simulated',d.simulated,'kind',s.kind,'label',s.label,'seconds',s.seconds) FROM daily_summaries s JOIN devices d ON d.id=s.device_id WHERE d.organization_id=$1 AND s.day=$2::date AND s.timezone=$3 AND ($4='' OR d.id=$4) ORDER BY s.kind,s.seconds DESC LIMIT 1000`, user.OrganizationID, date, zone, device); err != nil {
			return err
		}
		// Aggregate all matching rows independently of the bounded presentation breakdown.
		return tx.QueryRow(r.Context(), `SELECT count(*),coalesce(sum(s.seconds) FILTER(WHERE s.kind='application'),0),coalesce(sum(s.seconds) FILTER(WHERE s.kind='browser'),0),coalesce(sum(s.seconds) FILTER(WHERE s.kind='idle'),0),coalesce(sum(s.seconds) FILTER(WHERE s.kind='locked'),0),coalesce(sum(s.seconds) FILTER(WHERE s.kind='gap'),0) FROM daily_summaries s JOIN devices d ON d.id=s.device_id WHERE d.organization_id=$1 AND s.day=$2::date AND s.timezone=$3 AND ($4='' OR d.id=$4)`, user.OrganizationID, date, zone, device).Scan(&rowCount, &applicationSeconds, &browserSeconds, &idleSeconds, &lockedSeconds, &gapSeconds)
	})
	if err != nil {
		return err
	}
	coverage := "partial_observations"
	if len(items) == 0 {
		coverage = "no_data"
	}
	return send(w, 200, map[string]any{"date": date, "timezone": zone, "items": items, "application_seconds": applicationSeconds, "browser_seconds": browserSeconds, "idle_seconds": idleSeconds, "locked_seconds": lockedSeconds, "gap_seconds": gapSeconds, "coverage": coverage, "updated_at": time.Now().UTC(), "limit": 1000, "row_count": rowCount, "truncated": rowCount > int64(len(items))})
}

type Schedule struct {
	Days         []int  `json:"days"`
	Start        string `json:"start"`
	End          string `json:"end"`
	Unrestricted bool   `json:"unrestricted"`
}

func validSchedule(s Schedule) bool {
	if s.Unrestricted {
		return true
	}
	if len(s.Days) < 1 || len(s.Days) > 7 {
		return false
	}
	seen := map[int]bool{}
	for _, day := range s.Days {
		if day < 0 || day > 6 || seen[day] {
			return false
		}
		seen[day] = true
	}
	start, err := time.Parse("15:04", s.Start)
	if err != nil {
		return false
	}
	end, err := time.Parse("15:04", s.End)
	return err == nil && end.After(start)
}
func (a *App) getSettings(w http.ResponseWriter, r *http.Request, user principal) error {
	var items []any
	err := inScope(r.Context(), a.db, user.scope(), func(tx pgx.Tx) (err error) {
		items, err = jsonRows(r.Context(), tx, "SELECT jsonb_build_object('name',name,'timezone',timezone,'idle_seconds',idle_seconds,'raw_retention_days',raw_retention_days,'summary_retention_days',summary_retention_days,'collection_schedule',collection_schedule) FROM organizations WHERE id=$1", user.OrganizationID)
		return err
	})
	if err != nil {
		return err
	}
	if len(items) == 0 {
		return missing()
	}
	return send(w, 200, items[0])
}
func (a *App) updateSettings(w http.ResponseWriter, r *http.Request, user principal) error {
	var input struct {
		Idle     int      `json:"idle_seconds"`
		Raw      int      `json:"raw_retention_days"`
		Summary  int      `json:"summary_retention_days"`
		Schedule Schedule `json:"collection_schedule"`
	}
	if err := decode(w, r, &input); err != nil {
		return err
	}
	if input.Idle < 60 || input.Idle > 3600 || input.Raw < 1 || input.Raw > 90 || input.Summary < input.Raw || input.Summary > 365 || !validSchedule(input.Schedule) {
		return invalid("invalid collection or retention settings")
	}
	schedule, _ := json.Marshal(input.Schedule)
	tx, err := beginScoped(r.Context(), a.db, user.scope())
	if err != nil {
		return err
	}
	defer tx.Rollback(r.Context())
	if _, err = tx.Exec(r.Context(), "UPDATE organizations SET idle_seconds=$1,raw_retention_days=$2,summary_retention_days=$3,collection_schedule=$4 WHERE id=$5", input.Idle, input.Raw, input.Summary, schedule, user.OrganizationID); err != nil {
		return err
	}
	if err = audit(r.Context(), tx, user.OrganizationID, user.ID, "settings_updated", user.OrganizationID); err != nil {
		return err
	}
	if err = tx.Commit(r.Context()); err != nil {
		return err
	}
	return send(w, 200, map[string]any{"status": "saved"})
}

// Cleanup enforces retention as the runtime role. Organization-wide steps run under the retention
// scope; activity deletes then run per organization, so policies confine each delete to one tenant
// and ordinary tenant transactions can never delete activity rows.
func Cleanup(ctx context.Context, db *pgxpool.Pool, now time.Time) error {
	var organizations []string
	err := inScope(ctx, db, retentionScope, func(tx pgx.Tx) error {
		for _, query := range []string{
			// Advance the irreversible acceptance floor before deleting deduplication evidence.
			"UPDATE organizations SET ingest_not_before=greatest(ingest_not_before,$1::timestamptz-make_interval(days=>raw_retention_days))",
			"DELETE FROM sessions WHERE expires_at<=$1::timestamptz",
			"DELETE FROM audit_events WHERE created_at<$1::timestamptz-interval '90 days'",
		} {
			if _, err := tx.Exec(ctx, query, now); err != nil {
				return err
			}
		}
		rows, err := tx.Query(ctx, "SELECT id FROM organizations ORDER BY id")
		if err != nil {
			return err
		}
		organizations, err = pgx.CollectRows(rows, pgx.RowTo[string])
		return err
	})
	if err != nil {
		return err
	}
	for _, organization := range organizations {
		err = inScope(ctx, db, retentionTenantScope(organization), func(tx pgx.Tx) error {
			for _, query := range []string{
				"DELETE FROM events e USING devices d,organizations o WHERE e.device_id=d.id AND d.organization_id=o.id AND o.id=$2 AND e.observed_at<$1::timestamptz-make_interval(days=>o.raw_retention_days)",
				"DELETE FROM daily_summaries s USING devices d,organizations o WHERE s.device_id=d.id AND d.organization_id=o.id AND o.id=$2 AND s.day<(($1::timestamptz AT TIME ZONE o.timezone)::date-o.summary_retention_days)",
			} {
				if _, err := tx.Exec(ctx, query, now, organization); err != nil {
					return err
				}
			}
			return nil
		})
		if err != nil {
			return err
		}
	}
	return nil
}
