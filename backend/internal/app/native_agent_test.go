package app

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestNativeEnrollmentPolicyAndEmployeeIsolation(t *testing.T) {
	db, server, owner, login := setupIntegration(t)
	ctx := context.Background()
	anonymous := &testClient{t: t, client: server.Client(), base: server.URL}
	org := owner.expect("POST", "/api/owner/organizations", map[string]any{"name": "Native tenant", "timezone": "Asia/Kolkata"}, "", 201)["id"].(string)
	owner.expect("POST", "/api/owner/organizations/"+org+"/admins", map[string]any{"email": "native@example.test", "password": "Strong-native-password-2026!"}, "", 201)
	admin := login("native@example.test", "Strong-native-password-2026!")
	key := owner.expect("POST", "/api/owner/organizations/"+org+"/keys", map[string]any{"count": 1}, "", 201)["keys"].([]any)[0].(map[string]any)
	input := map[string]any{"enrollment_key": key["secret"], "hostname": "NATIVE-FIXTURE", "os": "Windows 11", "agent_version": "m1-test", "simulated": false}
	enrolled := anonymous.expect("POST", "/api/agent/enroll", input, "", 201)
	device, token := enrolled["device_id"].(string), enrolled["device_token"].(string)
	anonymous.expect("POST", "/api/agent/enroll", input, "", 401)
	var simulated bool
	if err := db.QueryRow(ctx, "SELECT simulated FROM devices WHERE id=$1", device).Scan(&simulated); err != nil || simulated {
		t.Fatalf("real device flag: %v %v", simulated, err)
	}
	anonymous.expect("GET", "/api/agent/policy", nil, "", 401)
	owner.expect("GET", "/api/agent/policy", nil, "", 401)
	policy := anonymous.expect("GET", "/api/agent/policy", nil, token, 200)
	if policy["timezone"] != "Asia/Kolkata" || policy["valid_for_seconds"] != float64(86400) || policy["idle_seconds"] != float64(300) {
		t.Fatalf("invalid policy: %v", policy)
	}
	oldVersion := policy["policy_version"]
	again := anonymous.expect("GET", "/api/agent/policy", nil, token, 200)
	if again["policy_version"] != oldVersion {
		t.Fatal("stable policy changed version")
	}
	encoded, _ := json.Marshal(policy)
	if strings.Contains(string(encoded), token) || strings.Contains(string(encoded), key["secret"].(string)) {
		t.Fatal("policy leaked credentials")
	}
	path := "/api/org/devices/" + device + "/employee"
	owner.expect("PUT", path, map[string]any{"employee_id": "EMP-1"}, "", 403)
	admin.expect("PUT", path, map[string]any{"employee_id": strings.Repeat("x", 121)}, "", 400)
	admin.expect("PUT", path, map[string]any{"employee_id": " EMP-1 "}, "", 200)
	var employee string
	if err := db.QueryRow(ctx, "SELECT employee_id FROM devices WHERE id=$1", device).Scan(&employee); err != nil || employee != "EMP-1" {
		t.Fatalf("employee assignment: %q %v", employee, err)
	}
	otherOrg := owner.expect("POST", "/api/owner/organizations", map[string]any{"name": "Other", "timezone": "UTC"}, "", 201)["id"].(string)
	owner.expect("POST", "/api/owner/organizations/"+otherOrg+"/admins", map[string]any{"email": "other-native@example.test", "password": "Strong-native-password-2026!"}, "", 201)
	other := login("other-native@example.test", "Strong-native-password-2026!")
	other.expect("PUT", path, map[string]any{"employee_id": "cross-tenant"}, "", 404)
	hash, err := passwordHash("Strong-viewer-password-2026!")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(ctx, "INSERT INTO accounts(id,email,password_hash,role,organization_id) VALUES($1,$2,$3,'org_viewer',$4)", RandomToken(), "native-viewer@example.test", hash, org); err != nil {
		t.Fatal(err)
	}
	viewer := login("native-viewer@example.test", "Strong-viewer-password-2026!")
	viewer.expect("PUT", path, map[string]any{"employee_id": "forbidden"}, "", 403)
	var audits int
	if err = db.QueryRow(ctx, "SELECT count(*) FROM audit_events WHERE action='device_employee_assigned' AND target_id=$1", device).Scan(&audits); err != nil || audits != 1 {
		t.Fatalf("audit: %d %v", audits, err)
	}
	health := map[string]any{"schema_version": 2, "helper": "healthy", "extension": "missing", "collection_state": "collecting", "policy_version": oldVersion, "queue_events": 1, "queue_bytes": 1024, "lost_events": 3, "loss_epoch": "epoch-1", "last_error": "none"}
	anonymous.expect("POST", "/api/agent/heartbeat", health, token, 200)
	anonymous.expect("POST", "/api/agent/heartbeat", map[string]any{"helper": "healthy", "extension": "missing", "queue_events": 0}, token, 400)
	health["lost_events"] = 2
	anonymous.expect("POST", "/api/agent/heartbeat", health, token, 409)
	health["lost_events"] = 3
	health["queue_bytes"] = -1
	anonymous.expect("POST", "/api/agent/heartbeat", health, token, 400)
	detail := admin.expect("GET", "/api/org/devices/"+device, nil, "", 200)["device"].(map[string]any)
	if detail["health"].(map[string]any)["lost_events"] != float64(3) {
		t.Fatal("health not persisted")
	}
	admin.expect("POST", "/api/org/devices/"+device+"/revoke", map[string]any{}, "", 200)
	anonymous.expect("GET", "/api/agent/policy", nil, token, 401)
}

func TestTelemetryVersionCompatibilityAndCoverage(t *testing.T) {
	db, server, owner, _ := setupIntegration(t)
	anonymous := &testClient{t: t, client: server.Client(), base: server.URL}
	org := owner.expect("POST", "/api/owner/organizations", map[string]any{"name": "Versions", "timezone": "UTC"}, "", 201)["id"].(string)
	key := owner.expect("POST", "/api/owner/organizations/"+org+"/keys", map[string]any{"count": 1}, "", 201)["keys"].([]any)[0].(map[string]any)
	token := anonymous.expect("POST", "/api/agent/enroll", map[string]any{"enrollment_key": key["secret"], "hostname": "TEST", "os": "Windows", "agent_version": "m1", "simulated": true}, "", 201)["device_token"].(string)
	start := time.Now().UTC().Truncate(time.Second).Add(-time.Hour)
	payload := map[string]any{"start": start, "end": start.Add(time.Minute)}
	event := map[string]any{"event_id": "legacy", "session_id": "s", "sequence": 0, "observed_at": start.Add(time.Minute), "kind": "gap", "payload": payload}
	batch := map[string]any{"schema_version": 1, "events": []any{event}}
	anonymous.expect(http.MethodPost, "/api/agent/events", batch, token, 200)
	anonymous.expect(http.MethodPost, "/api/agent/events", batch, token, 200)
	event["event_id"] = "native-gap"
	event["sequence"] = 1
	payload["start"] = start.Add(time.Minute)
	payload["end"] = start.Add(2 * time.Minute)
	event["observed_at"] = start.Add(2 * time.Minute)
	payload["gap_reason"] = "helper_missing"
	anonymous.expect(http.MethodPost, "/api/agent/events", batch, token, 400)
	batch["schema_version"] = 2
	anonymous.expect(http.MethodPost, "/api/agent/events", batch, token, 200)
	anonymous.expect(http.MethodPost, "/api/agent/events", batch, token, 200)
	payload["gap_reason"] = "arbitrary"
	anonymous.expect(http.MethodPost, "/api/agent/events", batch, token, 400)
	batch["schema_version"] = 3
	anonymous.expect(http.MethodPost, "/api/agent/events", batch, token, 400)
	var count int
	if err := db.QueryRow(context.Background(), "SELECT count(*) FROM events WHERE wire_version=2").Scan(&count); err != nil || count != 1 {
		t.Fatalf("v2 persistence %d %v", count, err)
	}
}
