package app

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestSessionExpiryViewerAndInputBoundaries(t *testing.T) {
	db, server, owner, login := setupIntegration(t)
	ctx := context.Background()
	org := owner.expect("POST", "/api/owner/organizations", map[string]any{"name": "A '; DROP TABLE devices; --", "timezone": "UTC"}, "", 201)["id"].(string)
	hash, err := passwordHash("Strong-viewer-password-2026!")
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec(ctx, "INSERT INTO accounts(id,email,password_hash,role,organization_id) VALUES($1,'viewer@example.test',$2,'org_viewer',$3)", RandomToken(), hash, org)
	if err != nil {
		t.Fatal(err)
	}
	viewer := login("viewer@example.test", "Strong-viewer-password-2026!")
	viewer.expect("GET", "/api/org/devices", nil, "", 200)
	viewer.expect("PUT", "/api/org/settings", map[string]any{}, "", 403)
	viewer.expect("POST", "/api/org/devices/guess/revoke", map[string]any{}, "", 403)
	owner.expect("GET", "/api/org/settings", nil, "", 403)
	_, err = db.Exec(ctx, "UPDATE sessions SET expires_at=now()-interval '1 minute' WHERE account_id IN (SELECT id FROM accounts WHERE email='viewer@example.test')")
	if err != nil {
		t.Fatal(err)
	}
	viewer.expect("GET", "/api/auth/me", nil, "", 401)
	owner.expect("POST", "/api/owner/organizations", map[string]any{"name": "X", "timezone": "UTC", "role": "org_admin"}, "", 400)
	owner.expect("POST", "/api/owner/organizations", map[string]any{"name": "X", "timezone": "Not/AZone"}, "", 400)
	// The body size must be rejected before it can be persisted or processed by SQL.
	body := []byte(`{"name":"` + strings.Repeat("x", (1<<20)+100) + `","timezone":"UTC"}`)
	req, _ := http.NewRequest("POST", server.URL+"/api/owner/organizations", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", server.URL)
	req.Header.Set("X-CSRF-Token", owner.csrf)
	response, err := owner.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != 413 {
		t.Fatalf("oversized body returned %d", response.StatusCode)
	}
	// Reloading /me must keep another tab's session CSRF token usable.
	me := owner.expect("GET", "/api/auth/me", nil, "", 200)
	if me["csrf_token"] != owner.csrf {
		t.Fatal("session reload invalidates other tabs")
	}
	if _, err = db.Exec(ctx, "SELECT 1 FROM devices LIMIT 0"); err != nil {
		t.Fatal("SQL injection damaged schema")
	}
	if err = BootstrapOwner(ctx, db, "replacement@example.test", "Strong-replacement-password!"); err == nil {
		t.Fatal("bootstrap replaced existing owner")
	}
}

func TestRetentionPreservesIndependentSummaryWindow(t *testing.T) {
	db, _, owner, _ := setupIntegration(t)
	ctx := context.Background()
	org := owner.expect("POST", "/api/owner/organizations", map[string]any{"name": "Retention fixture", "timezone": "UTC"}, "", 201)["id"].(string)
	device := RandomToken()
	_, err := db.Exec(ctx, "INSERT INTO devices(id,organization_id,hostname,os,agent_version,simulated,token_hash) VALUES($1,$2,'fixture','Windows','m0',true,$3)", device, org, digest(RandomToken()))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)
	_, err = db.Exec(ctx, "INSERT INTO events(device_id,event_id,session_id,sequence,observed_at,kind,payload,content_hash) VALUES($1,'expired-event','session',1,$2,'service','{}','hash')", device, now.AddDate(0, 0, -8))
	if err != nil {
		t.Fatal(err)
	}
	for _, days := range []int{8, 31} {
		_, err = db.Exec(ctx, "INSERT INTO daily_summaries(device_id,day,timezone,kind,label,seconds) VALUES($1,$2::date,'UTC','application',$3,600)", device, now.AddDate(0, 0, -days).Format("2006-01-02"), string(rune('a'+days)))
		if err != nil {
			t.Fatal(err)
		}
	}
	if err = Cleanup(ctx, db, now); err != nil {
		t.Fatal(err)
	}
	var events, summaries int
	db.QueryRow(ctx, "SELECT count(*) FROM events").Scan(&events)
	db.QueryRow(ctx, "SELECT count(*) FROM daily_summaries").Scan(&summaries)
	if events != 0 || summaries != 1 {
		t.Fatalf("cleanup events=%d summaries=%d; wanted 0/1", events, summaries)
	}
}

func TestEventValidation(t *testing.T) {
	now := time.Now().UTC()
	removed := Event{ID: "removed", Session: "session", Sequence: 2, Observed: now, Kind: "service", Payload: Payload{Service: "Spooler", State: "removed", StartupType: "unknown"}}
	if err := validateEvent(removed, now, 7); err != nil {
		t.Fatalf("removed service must be reportable: %v", err)
	}
	valid := Event{ID: "one", Session: "session", Sequence: 1, Observed: now, Kind: "browser", Payload: Payload{Hostname: "docs.example.com", Start: now.Add(-time.Minute), End: now}}
	if err := validateEvent(valid, now, 7); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name   string
		mutate func(*Event)
	}{
		{"full URL", func(e *Event) { e.Payload.Hostname = "https://example.com/private?token=secret" }},
		{"title", func(e *Event) { e.Payload.App = "confidential document title" }},
		{"clock ahead", func(e *Event) { e.Observed = now.Add(6 * time.Minute) }},
		{"expired", func(e *Event) { e.Observed = now.AddDate(0, 0, -8) }},
		{"negative sequence", func(e *Event) { e.Sequence = -1 }},
		{"inverted interval", func(e *Event) { e.Payload.End = e.Payload.Start.Add(-time.Second) }},
		{"oversized ID", func(e *Event) { e.ID = strings.Repeat("x", 129) }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			event := valid
			test.mutate(&event)
			if validateEvent(event, now, 7) == nil {
				t.Fatal("invalid event accepted")
			}
		})
	}
	// Decoder must reject sensitive fields even if the event kind otherwise looks valid.
	var e Event
	decoder := json.NewDecoder(strings.NewReader(`{"event_id":"x","password":"secret"}`))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&e) == nil {
		t.Fatal("unknown sensitive field accepted")
	}
}

func TestNativePolicyAgeBound(t *testing.T) {
	health := nativeHealth{Version: 2, Helper: "healthy", Extension: "missing", State: "collecting", Policy: "v1", PolicyAge: 86400, Epoch: "epoch", Error: "none"}
	if !validHealth(health) {
		t.Fatal("valid policy age rejected")
	}
	health.PolicyAge = 86401
	if validHealth(health) {
		t.Fatal("out-of-range policy age accepted")
	}
}
