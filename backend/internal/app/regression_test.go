package app

import (
	"context"
	"encoding/json"
	"testing"
	"time"
)

func TestReportTotalsAndRetentionReplayBoundary(t *testing.T) {
	db, runtimeDB, server, owner, login := setupIntegrationPools(t)
	ctx := context.Background()
	org := owner.expect("POST", "/api/owner/organizations", map[string]any{"name": "Report integrity fixtures", "timezone": "UTC"}, "", 201)["id"].(string)
	owner.expect("POST", "/api/owner/organizations/"+org+"/admins", map[string]any{"email": "reports@example.test", "password": "Strong-report-password-2026!"}, "", 201)
	admin := login("reports@example.test", "Strong-report-password-2026!")
	now := time.Now().UTC().Truncate(time.Second)
	wideDevice := RandomToken()
	token := RandomToken()
	_, err := db.Exec(ctx, "INSERT INTO devices(id,organization_id,hostname,os,agent_version,simulated,token_hash) VALUES($1,$2,'wide-report','Windows','m0',true,$3)", wideDevice, org, digest(token))
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec(ctx, "INSERT INTO daily_summaries(device_id,day,timezone,kind,label,seconds) SELECT $1,$2::date,'UTC','application','app-'||n,1 FROM generate_series(1,1001) n", wideDevice, now.Format("2006-01-02"))
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec(ctx, "INSERT INTO daily_summaries(device_id,day,timezone,kind,label,seconds) VALUES($1,$2::date,'UTC','browser','docs.example.com',300)", wideDevice, now.Format("2006-01-02"))
	if err != nil {
		t.Fatal(err)
	}
	t.Run("totals include all rows beyond bounded detail", func(t *testing.T) {
		result := admin.expect("GET", "/api/org/reports/daily?date="+now.Format("2006-01-02")+"&device_id="+wideDevice, nil, "", 200)
		if result["application_seconds"] != float64(1001) || result["browser_seconds"] != float64(300) {
			t.Fatalf("totals silently truncated: application=%v browser=%v", result["application_seconds"], result["browser_seconds"])
		}
		if result["truncated"] != true || len(result["items"].([]any)) != 1000 {
			t.Fatal("bounded detail must expose truncation independently of totals")
		}
	})
	t.Run("retention increase does not reopen expired replay window", func(t *testing.T) {
		oldStart := now.AddDate(0, 0, -8)
		event := Event{ID: "expired-original", Session: "old-session", Sequence: 1, Observed: oldStart.Add(600 * time.Second), Kind: "application", Payload: Payload{App: "editor.exe", Start: oldStart, End: oldStart.Add(600 * time.Second)}}
		raw, _ := json.Marshal(event)
		payload, _ := json.Marshal(event.Payload)
		_, err = db.Exec(ctx, "INSERT INTO events(device_id,event_id,session_id,sequence,observed_at,kind,starts_at,ends_at,payload,content_hash) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)", wideDevice, event.ID, event.Session, event.Sequence, event.Observed, event.Kind, event.Payload.Start, event.Payload.End, payload, digest(string(raw)))
		if err != nil {
			t.Fatal(err)
		}
		_, err = db.Exec(ctx, "INSERT INTO daily_summaries(device_id,day,timezone,kind,label,seconds) VALUES($1,$2::date,'UTC','application','editor.exe',600)", wideDevice, oldStart.Format("2006-01-02"))
		if err != nil {
			t.Fatal(err)
		}
		if err = Cleanup(ctx, runtimeDB, now); err != nil {
			t.Fatal(err)
		}
		admin.expect("PUT", "/api/org/settings", map[string]any{"idle_seconds": 300, "raw_retention_days": 30, "summary_retention_days": 30, "collection_schedule": map[string]any{"unrestricted": true}}, "", 200)
		anonymous := &testClient{t: t, client: server.Client(), base: server.URL}
		anonymous.expect("POST", "/api/agent/events", map[string]any{"schema_version": 1, "events": []Event{event}}, token, 400)
		var seconds int64
		if err = db.QueryRow(ctx, "SELECT seconds FROM daily_summaries WHERE device_id=$1 AND label='editor.exe'", wideDevice).Scan(&seconds); err != nil {
			t.Fatal(err)
		}
		if seconds != 600 {
			t.Fatalf("expired replay altered historical summary: %d", seconds)
		}
	})
}
