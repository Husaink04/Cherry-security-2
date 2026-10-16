package app

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

type testClient struct {
	t          *testing.T
	client     *http.Client
	base, csrf string
}

func (c *testClient) request(method, path string, body any, bearer string) (int, map[string]any) {
	c.t.Helper()
	var input io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			c.t.Fatal(err)
		}
		input = bytes.NewReader(data)
	}
	req, err := http.NewRequest(method, c.base+path, input)
	if err != nil {
		c.t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	if method != "GET" {
		req.Header.Set("Origin", c.base)
		req.Header.Set("X-CSRF-Token", c.csrf)
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	res, err := c.client.Do(req)
	if err != nil {
		c.t.Fatal(err)
	}
	defer res.Body.Close()
	var result map[string]any
	if err := json.NewDecoder(res.Body).Decode(&result); err != nil {
		c.t.Fatalf("%s %s returned invalid JSON: %v", method, path, err)
	}
	return res.StatusCode, result
}
func (c *testClient) expect(method, path string, body any, bearer string, want int) map[string]any {
	c.t.Helper()
	code, result := c.request(method, path, body, bearer)
	if code != want {
		c.t.Fatalf("%s %s: got %d want %d: %v", method, path, code, want, result)
	}
	return result
}
func setupIntegration(t *testing.T) (*pgxpool.Pool, *httptest.Server, *testClient, func(string, string) *testClient) {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set; real PostgreSQL integration test skipped")
	}
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(cfg.ConnConfig.Database, "_test") {
		t.Fatal("refusing integration test outside dedicated _test database")
	}
	schema := "test_" + RandomToken()[:16]
	ctx := context.Background()
	bootstrap, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = bootstrap.Exec(ctx, "CREATE SCHEMA "+schema); err != nil {
		t.Fatal(err)
	}
	cfg.ConnConfig.RuntimeParams["search_path"] = schema
	db, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err = Migrate(ctx, db); err != nil {
		t.Fatal(err)
	}
	if err = BootstrapOwner(ctx, db, "owner@example.test", "Strong-owner-password-2026!"); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(nil)
	// Race instrumentation makes bcrypt substantially slower; keep production cost 12 unchanged.
	server.Config.Handler = New(db, Config{Origin: "http://" + server.Listener.Addr().String(), RequestTimeout: 60 * time.Second})
	server.Start()
	t.Cleanup(func() {
		server.Close()
		db.Close()
		_, _ = bootstrap.Exec(ctx, "DROP SCHEMA "+schema+" CASCADE")
		bootstrap.Close()
	})
	login := func(email, password string) *testClient {
		jar, _ := cookiejar.New(nil)
		c := &testClient{t: t, client: &http.Client{Jar: jar, Timeout: 90 * time.Second}, base: server.URL}
		out := c.expect("POST", "/api/auth/login", map[string]any{"email": email, "password": password}, "", 200)
		c.csrf = out["csrf_token"].(string)
		return c
	}
	owner := login("owner@example.test", "Strong-owner-password-2026!")
	return db, server, owner, login
}

func TestM0Workflow(t *testing.T) {
	db, server, owner, login := setupIntegration(t)
	ctx := context.Background()
	anonymous := &testClient{t: t, client: server.Client(), base: server.URL}
	anonymous.expect("GET", "/api/org/devices", nil, "", 401)
	anonymous.expect("POST", "/api/auth/login", map[string]any{"email": "owner@example.test", "password": "wrong"}, "", 401)
	orgs := []string{}
	admins := []*testClient{}
	for i := 0; i < 2; i++ {
		o := owner.expect("POST", "/api/owner/organizations", map[string]any{"name": fmt.Sprintf("Fixture %d", i), "timezone": "Asia/Kolkata"}, "", 201)
		id := o["id"].(string)
		orgs = append(orgs, id)
		email := fmt.Sprintf("admin%d@example.test", i)
		owner.expect("POST", "/api/owner/organizations/"+id+"/admins", map[string]any{"email": email, "password": "Strong-admin-password-2026!"}, "", 201)
		admins = append(admins, login(email, "Strong-admin-password-2026!"))
	}
	admin := admins[0]
	admin.expect("POST", "/api/owner/organizations", map[string]any{"name": "Forbidden"}, "", 403)
	admin.expect("POST", "/api/owner/organizations/"+orgs[0]+"/keys", map[string]any{"count": 1}, "", 403)
	admins[1].expect("GET", "/api/owner/organizations/"+orgs[0]+"/keys", nil, "", 403)
	owner.expect("GET", "/api/org/devices", nil, "", 403)
	savedCSRF := admin.csrf
	admin.csrf = "wrong"
	admin.expect("POST", "/api/auth/logout", map[string]any{}, "", 403)
	admin.csrf = savedCSRF
	issue := func() map[string]any {
		return owner.expect("POST", "/api/owner/organizations/"+orgs[0]+"/keys", map[string]any{"count": 1}, "", 201)["keys"].([]any)[0].(map[string]any)
	}
	key := issue()
	secret := key["secret"].(string)
	meta := admin.expect("GET", "/api/org/keys", nil, "", 200)
	encoded, _ := json.Marshal(meta)
	if strings.Contains(string(encoded), secret) {
		t.Fatal("key secret leaked through metadata")
	}
	enrollment := map[string]any{"enrollment_key": secret, "hostname": "SIMULATED-WINDOWS", "os": "Windows fixture", "agent_version": "m0", "simulated": true}
	bad := map[string]any{"enrollment_key": secret, "hostname": "fake", "os": "Windows", "agent_version": "m0", "simulated": true, "organization_id": orgs[1]}
	anonymous.expect("POST", "/api/agent/enroll", bad, "", 400)
	// A single key must produce exactly one successful concurrent enrollment.
	var wg sync.WaitGroup
	codes := make(chan int, 2)
	responses := make(chan map[string]any, 2)
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			code, out := anonymous.request("POST", "/api/agent/enroll", enrollment, "")
			codes <- code
			if code == 201 {
				responses <- out
			}
		}()
	}
	wg.Wait()
	close(codes)
	success := 0
	for code := range codes {
		if code == 201 {
			success++
		} else if code != 401 {
			t.Fatalf("unexpected redemption status %d", code)
		}
	}
	if success != 1 {
		t.Fatalf("race produced %d successful devices", success)
	}
	enrolled := <-responses
	device := enrolled["device_id"].(string)
	token := enrolled["device_token"].(string)
	revoked := issue()
	owner.expect("POST", "/api/owner/keys/"+revoked["id"].(string)+"/revoke", map[string]any{}, "", 200)
	enrollment["enrollment_key"] = revoked["secret"]
	anonymous.expect("POST", "/api/agent/enroll", enrollment, "", 401)
	expired := issue()
	_, err := db.Exec(ctx, "UPDATE enrollment_keys SET expires_at=now()-interval '1 hour' WHERE id=$1", expired["id"])
	if err != nil {
		t.Fatal(err)
	}
	enrollment["enrollment_key"] = expired["secret"]
	anonymous.expect("POST", "/api/agent/enroll", enrollment, "", 401)
	admins[1].expect("GET", "/api/org/devices/"+device, nil, "", 404)
	admins[1].expect("GET", "/api/org/devices/"+device+"/services", nil, "", 404)
	admins[1].expect("POST", "/api/org/devices/"+device+"/revoke", map[string]any{}, "", 404)
	anonymous.expect("POST", "/api/agent/heartbeat", map[string]any{"helper": "healthy", "extension": "simulated"}, "", 401)
	anonymous.expect("POST", "/api/agent/heartbeat", map[string]any{"helper": "healthy", "extension": "simulated"}, token, 200)
	start := time.Now().UTC().Truncate(time.Hour).Add(-time.Hour)
	makeEvent := func(id, kind string, offset, duration int, payload map[string]any) map[string]any {
		if kind != "service" {
			payload["start"] = start.Add(time.Duration(offset) * time.Second).Format(time.RFC3339)
			payload["end"] = start.Add(time.Duration(offset+duration) * time.Second).Format(time.RFC3339)
		}
		return map[string]any{"event_id": id, "session_id": "fixture-session", "sequence": offset + 1, "observed_at": start.Add(time.Duration(offset+duration) * time.Second).Format(time.RFC3339), "kind": kind, "payload": payload}
	}
	events := []any{makeEvent("app-1", "application", 0, 600, map[string]any{"app": "chrome.exe"}), makeEvent("web-1", "browser", 0, 300, map[string]any{"hostname": "docs.example.com"}), makeEvent("svc-new", "service", 600, 0, map[string]any{"service": "Spooler", "state": "running", "startup_type": "automatic"}), makeEvent("svc-old", "service", 0, 0, map[string]any{"service": "Spooler", "state": "stopped", "startup_type": "automatic"})}
	batch := map[string]any{"schema_version": 1, "events": events}
	anonymous.expect("POST", "/api/agent/events", batch, token, 200)
	anonymous.expect("POST", "/api/agent/events", batch, token, 200)
	var count int
	db.QueryRow(ctx, "SELECT count(*) FROM events").Scan(&count)
	if count != 4 {
		t.Fatalf("replay duplicated events: %d", count)
	}
	conflict := makeEvent("app-1", "application", 0, 600, map[string]any{"app": "changed.exe"})
	anonymous.expect("POST", "/api/agent/events", map[string]any{"schema_version": 1, "events": []any{conflict}}, token, 409)
	invalid := makeEvent("bad-domain", "browser", 1000, 30, map[string]any{"hostname": "https://example.com/private?secret=yes"})
	valid := makeEvent("atomic-valid", "application", 1000, 30, map[string]any{"app": "editor.exe"})
	anonymous.expect("POST", "/api/agent/events", map[string]any{"schema_version": 1, "events": []any{valid, invalid}}, token, 400)
	db.QueryRow(ctx, "SELECT count(*) FROM events").Scan(&count)
	if count != 4 {
		t.Fatal("invalid batch partially committed")
	}
	overlap := makeEvent("overlap", "application", 1, 20, map[string]any{"app": "other.exe"})
	anonymous.expect("POST", "/api/agent/events", map[string]any{"schema_version": 1, "events": []any{overlap}}, token, 409)
	report := admin.expect("GET", "/api/org/reports/daily?date="+start.In(mustLocation("Asia/Kolkata")).Format("2006-01-02")+"&device_id="+device, nil, "", 200)
	if report["application_seconds"] != float64(600) || report["browser_seconds"] != float64(300) {
		t.Fatalf("incorrect totals %v", report)
	}
	detail := admin.expect("GET", "/api/org/devices/"+device, nil, "", 200)
	if gaps, ok := detail["sequence_gap_count"].(float64); !ok || gaps < 1 {
		t.Fatal("missing event sequences must be visible in device coverage")
	}
	service := admin.expect("GET", "/api/org/devices/"+device+"/services", nil, "", 200)["services"].([]any)[0].(map[string]any)
	if service["state"] != "running" {
		t.Fatalf("old service overwrote state: %v", service)
	}
	owner.expect("GET", "/api/org/reports/daily?date=2026-10-16", nil, "", 403)
	admin.expect("POST", "/api/org/devices/"+device+"/revoke", map[string]any{}, "", 200)
	anonymous.expect("POST", "/api/agent/heartbeat", map[string]any{}, token, 401)
	anonymous.expect("POST", "/api/agent/events", batch, token, 401)
	var secrets int
	db.QueryRow(ctx, "SELECT count(*) FROM audit_events WHERE detail::text LIKE '%' || $1 || '%'", secret).Scan(&secrets)
	if secrets != 0 {
		t.Fatal("audit contains secret")
	}
	admin.expect("POST", "/api/auth/logout", map[string]any{}, "", 200)
	admin.expect("GET", "/api/auth/me", nil, "", 401)
}
func mustLocation(name string) *time.Location {
	l, err := time.LoadLocation(name)
	if err != nil {
		panic(err)
	}
	return l
}

func TestDaySplitting(t *testing.T) {
	cases := []struct {
		name, zone, start, end string
		want                   map[string]int64
	}{
		{"midnight", "Asia/Kolkata", "2026-10-15T18:25:00Z", "2026-10-15T18:35:00Z", map[string]int64{"2026-10-15": 300, "2026-10-16": 300}},
		{"DST", "America/New_York", "2026-11-01T04:00:00Z", "2026-11-02T05:00:00Z", map[string]int64{"2026-11-01": 90000}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			start, _ := time.Parse(time.RFC3339, c.start)
			end, _ := time.Parse(time.RFC3339, c.end)
			got := SplitDays(start, end, mustLocation(c.zone))
			a, _ := json.Marshal(got)
			b, _ := json.Marshal(c.want)
			if string(a) != string(b) {
				t.Fatalf("got %s want %s", a, b)
			}
		})
	}
}
