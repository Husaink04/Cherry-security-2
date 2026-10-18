package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
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
	db, runtimeDB, _, owner, _ := setupIntegrationPools(t)
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
	// Cleanup runs as the runtime role so its retention scopes are exercised under row-level security.
	if err = Cleanup(ctx, runtimeDB, now); err != nil {
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

func TestWindowLimiter(t *testing.T) {
	start := time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)
	limiter := newWindowLimiter(2, time.Minute, 2)
	if !limiter.add("a", start) || !limiter.add("a", start) || limiter.add("a", start) {
		t.Fatal("limit not enforced at the third attempt")
	}
	later := start.Add(time.Minute)
	if !limiter.add("a", later) || !limiter.add("b", later) {
		t.Fatal("window did not reset or second key refused")
	}
	if limiter.add("c", later) {
		t.Fatal("full key table must refuse new keys instead of growing")
	}
	expired := later.Add(time.Minute)
	if !limiter.add("c", expired) || !limiter.add("c", expired) || limiter.add("c", expired) {
		t.Fatal("expired keys were not pruned or limit not enforced")
	}
	limiter.reset("c")
	if !limiter.add("c", expired) {
		t.Fatal("reset did not clear attempts")
	}
}

func TestLoginClientAddress(t *testing.T) {
	request := httptest.NewRequest("POST", "/api/auth/login", nil)
	request.RemoteAddr = "172.18.0.5:41234"
	request.Header.Set("X-Real-IP", "203.0.113.9")
	direct := &App{}
	if got := direct.clientAddress(request); got != "172.18.0.5" {
		t.Fatalf("untrusted header used to choose the rate-limit key: %s", got)
	}
	proxied := &App{config: Config{TrustProxyHeader: true}}
	if got := proxied.clientAddress(request); got != "203.0.113.9" {
		t.Fatalf("trusted proxy address ignored: %s", got)
	}
	request.Header.Set("X-Real-IP", "not-an-ip")
	if got := proxied.clientAddress(request); got != "172.18.0.5" {
		t.Fatalf("invalid proxy header must fall back to the connection address: %s", got)
	}
}

func TestLoginThrottlingAndFailureAudit(t *testing.T) {
	db, server, owner, login := setupIntegration(t)
	ctx := context.Background()
	org := owner.expect("POST", "/api/owner/organizations", map[string]any{"name": "Login fixture", "timezone": "UTC"}, "", 201)["id"].(string)
	owner.expect("POST", "/api/owner/organizations/"+org+"/admins", map[string]any{"email": "locked@example.test", "password": "Strong-locked-password-2026!"}, "", 201)
	owner.expect("POST", "/api/owner/organizations/"+org+"/admins", map[string]any{"email": "other@example.test", "password": "Strong-other-password-2026!"}, "", 201)
	anonymous := &testClient{t: t, client: server.Client(), base: server.URL}
	for range 5 {
		anonymous.expect("POST", "/api/auth/login", map[string]any{"email": "locked@example.test", "password": "wrong-password-value"}, "", 401)
	}
	// The correct password is refused once the account is locked, so guessing cannot continue.
	anonymous.expect("POST", "/api/auth/login", map[string]any{"email": "locked@example.test", "password": "Strong-locked-password-2026!"}, "", 429)
	// Other accounts on the same client remain usable; one account cannot lock out everyone.
	login("other@example.test", "Strong-other-password-2026!")
	var failures, leaked int
	db.QueryRow(ctx, "SELECT count(*) FROM audit_events WHERE action='login_failed' AND organization_id=$1", org).Scan(&failures)
	if failures != 5 {
		t.Fatalf("expected 5 audited login failures, got %d", failures)
	}
	db.QueryRow(ctx, "SELECT count(*) FROM audit_events WHERE target_id LIKE '%@%' OR detail::text LIKE '%@%' OR detail::text LIKE '%wrong-password%'").Scan(&leaked)
	if leaked != 0 {
		t.Fatal("audit records contain submitted credentials")
	}
	// Unknown accounts throttle identically so lockouts do not reveal which emails exist.
	for range 5 {
		anonymous.expect("POST", "/api/auth/login", map[string]any{"email": "ghost@example.test", "password": "wrong-password-value"}, "", 401)
	}
	anonymous.expect("POST", "/api/auth/login", map[string]any{"email": "ghost@example.test", "password": "wrong-password-value"}, "", 429)
}

func TestLoginClientLimit(t *testing.T) {
	// Limits are checked before any password hash or database work, so a nil database proves that ordering.
	origin := "http://127.0.0.1:8080"
	a := &App{config: Config{Origin: origin},
		globalLogins:  newWindowLimiter(globalLoginLimit, time.Minute, 1),
		clientLogins:  newWindowLimiter(clientLoginLimit, time.Minute, loginLimiterKeys),
		accountLogins: newWindowLimiter(accountLoginLimit, 15*time.Minute, loginLimiterKeys)}
	now := time.Now()
	for range clientLoginLimit {
		a.clientLogins.add("192.0.2.10", now)
	}
	for range accountLoginLimit {
		a.accountLogins.add(digest("login:other@example.test"), now)
	}
	attempt := func(address, email string) (int, string) {
		request := httptest.NewRequest("POST", "/api/auth/login", strings.NewReader(`{"email":"`+email+`","password":"wrong-password-value"}`))
		request.RemoteAddr = address
		request.Header.Set("Origin", origin)
		request.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		var rejected *apiError
		if err := a.login(response, request); !errors.As(err, &rejected) {
			t.Fatalf("expected a rate-limit rejection, got %v", err)
		}
		return rejected.status, response.Header().Get("Retry-After")
	}
	if status, retry := attempt("192.0.2.10:41234", "probe@example.test"); status != 429 || retry != "60" {
		t.Fatalf("client over its limit got %d (Retry-After %q)", status, retry)
	}
	// Another client passes the client limit and stops only at its own account lock.
	if status, retry := attempt("198.51.100.7:52000", "other@example.test"); status != 429 || retry != "900" {
		t.Fatalf("one client's limit affected another client: %d (Retry-After %q)", status, retry)
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
