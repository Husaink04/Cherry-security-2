package app

import (
	"context"
	"encoding/json"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestOneStepTenantProvisioning(t *testing.T) {
	db, _, owner, login := setupIntegration(t)
	ctx := context.Background()
	created := owner.expect("POST", "/api/owner/organizations", map[string]any{"name": "Northwind Tenant", "timezone": "UTC", "admin": map[string]any{"email": "first-admin@example.test", "password": "Strong-first-password-2026!"}, "key_count": 2}, "", 201)
	if created["admin_id"] == nil || len(created["keys"].([]any)) != 2 {
		t.Fatalf("one-step creation incomplete: %v", created)
	}
	login("first-admin@example.test", "Strong-first-password-2026!").expect("GET", "/api/org/settings", nil, "", 200)
	listed := owner.expect("GET", "/api/owner/organizations?q=northwind", nil, "", 200)["organizations"].([]any)
	if len(listed) != 1 {
		t.Fatalf("case-insensitive search returned %d organizations", len(listed))
	}
	org := listed[0].(map[string]any)
	if org["admin_count"] != float64(1) || org["unused_key_count"] != float64(2) || org["active_device_count"] != float64(0) {
		t.Fatalf("unexpected provisioning counts: %v", org)
	}
	if got := owner.expect("GET", "/api/owner/organizations?q="+url.QueryEscape("%"), nil, "", 200)["organizations"].([]any); len(got) != 0 {
		t.Fatal("search treated % as a wildcard")
	}
	// Every rejected request must leave no partial tenant behind.
	rejected := []struct {
		body map[string]any
		want int
	}{
		{map[string]any{"name": "Duplicate Admin Tenant", "timezone": "UTC", "admin": map[string]any{"email": "first-admin@example.test", "password": "Strong-other-password-2026!"}}, 409},
		{map[string]any{"name": "Weak Password Tenant", "timezone": "UTC", "admin": map[string]any{"email": "weak@example.test", "password": "short"}}, 400},
		{map[string]any{"name": "Partial Admin Tenant", "timezone": "UTC", "admin": map[string]any{"email": "partial@example.test"}}, 400},
		{map[string]any{"name": "Too Many Keys Tenant", "timezone": "UTC", "key_count": 101}, 400},
		{map[string]any{"name": "Injected Tenant", "timezone": "UTC", "admin": map[string]any{"email": "x@example.test", "password": "Strong-x-password-2026!", "role": "product_owner"}}, 400},
	}
	for _, test := range rejected {
		owner.expect("POST", "/api/owner/organizations", test.body, "", test.want)
		var count int
		if err := db.QueryRow(ctx, "SELECT count(*) FROM organizations WHERE name=$1", test.body["name"]).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count != 0 {
			t.Fatalf("rejected request left organization %q behind", test.body["name"])
		}
	}
	// Creating without an administrator or keys still works for staged provisioning.
	staged := owner.expect("POST", "/api/owner/organizations", map[string]any{"name": "Staged Tenant", "timezone": "Asia/Kolkata"}, "", 201)
	if staged["admin_id"] != nil || staged["keys"] != nil {
		t.Fatalf("staged creation returned extra resources: %v", staged)
	}
}

type tenantFixture struct {
	org, device, token, keyID, email, hostname, app, domain, service string
	admin, viewer                                                    *testClient
}

func TestTenantIsolationMatrix(t *testing.T) {
	db, server, owner, login := setupIntegration(t)
	ctx := context.Background()
	anonymous := &testClient{t: t, client: server.Client(), base: server.URL}
	start := time.Now().UTC().Truncate(time.Hour).Add(-time.Hour)
	date := start.Format("2006-01-02")
	tenants := []*tenantFixture{}
	for _, name := range []string{"alpha", "beta"} {
		created := owner.expect("POST", "/api/owner/organizations", map[string]any{"name": "Tenant " + name, "timezone": "UTC", "admin": map[string]any{"email": name + "-admin@example.test", "password": "Strong-tenant-password-2026!"}, "key_count": 1}, "", 201)
		f := &tenantFixture{org: created["id"].(string), email: name + "-admin@example.test", hostname: strings.ToUpper(name) + "-ONLY-HOST", app: name + "-only.exe", domain: name + "-only.example.com", service: name + "OnlyService"}
		key := created["keys"].([]any)[0].(map[string]any)
		f.keyID = key["id"].(string)
		hash, err := passwordHash("Strong-viewer-password-2026!")
		if err != nil {
			t.Fatal(err)
		}
		if _, err = db.Exec(ctx, "INSERT INTO accounts(id,email,password_hash,role,organization_id) VALUES($1,$2,$3,'org_viewer',$4)", RandomToken(), name+"-viewer@example.test", hash, f.org); err != nil {
			t.Fatal(err)
		}
		f.admin = login(name+"-admin@example.test", "Strong-tenant-password-2026!")
		f.viewer = login(name+"-viewer@example.test", "Strong-viewer-password-2026!")
		enrolled := anonymous.expect("POST", "/api/agent/enroll", map[string]any{"enrollment_key": key["secret"], "hostname": f.hostname, "os": "Windows fixture", "agent_version": "m1", "simulated": true}, "", 201)
		f.device, f.token = enrolled["device_id"].(string), enrolled["device_token"].(string)
		anonymous.expect("POST", "/api/agent/heartbeat", map[string]any{"helper": "simulated", "extension": "simulated"}, f.token, 200)
		interval := func(kind string, offset int, payload map[string]any) map[string]any {
			payload["start"] = start.Add(time.Duration(offset) * time.Second).Format(time.RFC3339)
			payload["end"] = start.Add(time.Duration(offset+300) * time.Second).Format(time.RFC3339)
			return map[string]any{"event_id": "shared-" + kind, "session_id": "session", "sequence": offset + 1, "observed_at": start.Add(time.Duration(offset+300) * time.Second).Format(time.RFC3339), "kind": kind, "payload": payload}
		}
		// Both tenants reuse the same event IDs; conflicts and deduplication must stay per device.
		events := []any{
			interval("application", 0, map[string]any{"app": f.app}),
			interval("browser", 0, map[string]any{"hostname": f.domain}),
			map[string]any{"event_id": "shared-service", "session_id": "session", "sequence": 900, "observed_at": start.Add(600 * time.Second).Format(time.RFC3339), "kind": "service", "payload": map[string]any{"service": f.service, "state": "running", "startup_type": "automatic"}},
		}
		anonymous.expect("POST", "/api/agent/events", map[string]any{"schema_version": 1, "events": events}, f.token, 200)
		tenants = append(tenants, f)
	}
	alpha, beta := tenants[0], tenants[1]
	alpha.admin.expect("PUT", "/api/org/settings", map[string]any{"idle_seconds": 900, "raw_retention_days": 14, "summary_retention_days": 60, "collection_schedule": map[string]any{"unrestricted": true}}, "", 200)
	alpha.admin.expect("PUT", "/api/org/devices/"+alpha.device+"/employee", map[string]any{"employee_id": "alpha-employee-7"}, "", 200)
	for _, pair := range [][2]*tenantFixture{{alpha, beta}, {beta, alpha}} {
		victim, reader := pair[0], pair[1]
		markers := []string{victim.org, victim.device, victim.keyID, victim.email, victim.hostname, victim.app, victim.domain, victim.service}
		if victim == alpha {
			markers = append(markers, "alpha-employee-7")
		}
		var seen strings.Builder
		record := func(result map[string]any) {
			data, _ := json.Marshal(result)
			seen.Write(data)
		}
		for _, client := range []*testClient{reader.admin, reader.viewer} {
			record(client.expect("GET", "/api/org/devices", nil, "", 200))
			record(client.expect("GET", "/api/org/reports/daily?date="+date, nil, "", 200))
			record(client.expect("GET", "/api/org/settings", nil, "", 200))
			client.expect("GET", "/api/org/devices/"+victim.device, nil, "", 404)
			client.expect("GET", "/api/org/devices/"+victim.device+"/services", nil, "", 404)
			client.expect("GET", "/api/org/reports/daily?date="+date+"&device_id="+victim.device, nil, "", 404)
		}
		record(reader.admin.expect("GET", "/api/org/keys", nil, "", 200))
		record(reader.admin.expect("GET", "/api/org/audit", nil, "", 200))
		record(reader.admin.expect("GET", "/api/org/devices/"+reader.device, nil, "", 200))
		record(reader.admin.expect("GET", "/api/org/devices/"+reader.device+"/services", nil, "", 200))
		reader.admin.expect("PUT", "/api/org/devices/"+victim.device+"/employee", map[string]any{"employee_id": "hijacked"}, "", 404)
		reader.admin.expect("POST", "/api/org/devices/"+victim.device+"/revoke", map[string]any{}, "", 404)
		output := seen.String()
		for _, marker := range markers {
			if strings.Contains(output, marker) {
				t.Fatalf("tenant %s can see tenant %s marker %q", reader.org, victim.org, marker)
			}
		}
		// Each tenant still sees its own data, so the empty-result checks above are meaningful.
		own := reader.admin.expect("GET", "/api/org/reports/daily?date="+date, nil, "", 200)
		if own["application_seconds"] != float64(300) || own["browser_seconds"] != float64(300) {
			t.Fatalf("tenant %s lost its own totals: %v", reader.org, own)
		}
	}
	betaSettings := beta.admin.expect("GET", "/api/org/settings", nil, "", 200)
	if betaSettings["idle_seconds"] != float64(300) || betaSettings["raw_retention_days"] != float64(7) {
		t.Fatalf("alpha's settings change reached beta: %v", betaSettings)
	}
	var employee string
	if err := db.QueryRow(ctx, "SELECT employee_id FROM devices WHERE id=$1", alpha.device).Scan(&employee); err != nil || employee != "alpha-employee-7" {
		t.Fatalf("cross-tenant employee write changed alpha's device: %q %v", employee, err)
	}
	var revoked int
	if err := db.QueryRow(ctx, "SELECT count(*) FROM devices WHERE revoked_at IS NOT NULL").Scan(&revoked); err != nil || revoked != 0 {
		t.Fatalf("cross-tenant revocation succeeded: %d %v", revoked, err)
	}
	// Device tokens carry their own tenant; neither can reach organization routes.
	anonymous.expect("GET", "/api/org/devices", nil, alpha.token, 401)
	for _, path := range []string{"/api/org/devices", "/api/org/devices/" + alpha.device, "/api/org/reports/daily?date=" + date, "/api/org/keys", "/api/org/settings", "/api/org/audit"} {
		owner.expect("GET", path, nil, "", 403)
	}
}
