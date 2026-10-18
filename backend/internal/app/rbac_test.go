package app

import (
	"context"
	"encoding/json"
	"net/url"
	"strings"
	"testing"
)

func TestOrganizationAuditAndRoleBoundaries(t *testing.T) {
	db, _, owner, login := setupIntegration(t)
	ctx := context.Background()
	orgs := []string{}
	for _, name := range []string{"Audit A", "Audit B"} {
		orgs = append(orgs, owner.expect("POST", "/api/owner/organizations", map[string]any{"name": name, "timezone": "UTC"}, "", 201)["id"].(string))
	}
	owner.expect("POST", "/api/owner/organizations/"+orgs[0]+"/admins", map[string]any{"email": "audit-a@example.test", "password": "Strong-audit-password-2026!"}, "", 201)
	other := owner.expect("POST", "/api/owner/organizations/"+orgs[1]+"/admins", map[string]any{"email": "audit-b@example.test", "password": "Strong-audit-password-2026!"}, "", 201)["id"].(string)
	hash, err := passwordHash("Strong-viewer-password-2026!")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(ctx, "INSERT INTO accounts(id,email,password_hash,role,organization_id) VALUES($1,'audit-viewer@example.test',$2,'org_viewer',$3)", RandomToken(), hash, orgs[0]); err != nil {
		t.Fatal(err)
	}
	admin := login("audit-a@example.test", "Strong-audit-password-2026!")
	adminB := login("audit-b@example.test", "Strong-audit-password-2026!")
	viewer := login("audit-viewer@example.test", "Strong-viewer-password-2026!")
	viewer.expect("GET", "/api/org/keys", nil, "", 403)
	viewer.expect("GET", "/api/org/audit", nil, "", 403)
	owner.expect("GET", "/api/org/audit", nil, "", 403)
	admin.expect("GET", "/api/org/keys", nil, "", 200)
	// One issuance transaction gives 100 events the same timestamp, which paging must not skip.
	keys := owner.expect("POST", "/api/owner/organizations/"+orgs[0]+"/keys", map[string]any{"count": 100}, "", 201)["keys"].([]any)
	// A forged cross-organization actor must not resolve to the other organization's email.
	if _, err = db.Exec(ctx, "INSERT INTO audit_events(id,organization_id,actor_id,action,target_id) VALUES($1,$2,$3,'settings_updated',$2)", RandomToken(), orgs[0], other); err != nil {
		t.Fatal(err)
	}
	var stored int
	if err = db.QueryRow(ctx, "SELECT count(*) FROM audit_events WHERE organization_id=$1", orgs[0]).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	path := "/api/org/audit"
	pages := 0
	var encoded strings.Builder
	for {
		page := admin.expect("GET", path, nil, "", 200)
		pages++
		events := page["events"].([]any)
		for _, value := range events {
			event := value.(map[string]any)
			id := event["id"].(string)
			if seen[id] {
				t.Fatalf("event %s returned twice across pages", id)
			}
			seen[id] = true
			if event["action"] == "organization_created" && event["actor"] != "Product Owner" {
				t.Fatalf("Product Owner actor not labeled: %v", event["actor"])
			}
			if event["action"] == "settings_updated" && event["actor"] != "unknown" {
				t.Fatalf("cross-organization actor resolved: %v", event["actor"])
			}
		}
		data, _ := json.Marshal(page)
		encoded.Write(data)
		if page["has_more"] != true {
			break
		}
		last := events[len(events)-1].(map[string]any)
		path = "/api/org/audit?before=" + url.QueryEscape(last["created_at"].(string)) + "&before_id=" + last["id"].(string)
	}
	if len(seen) != stored || pages < 2 {
		t.Fatalf("paging returned %d of %d events in %d pages", len(seen), stored, pages)
	}
	output := encoded.String()
	for _, forbidden := range []string{"owner@example.test", "audit-b@example.test", "Strong-"} {
		if strings.Contains(output, forbidden) {
			t.Fatalf("audit output leaked %q", forbidden)
		}
	}
	for _, key := range keys {
		if strings.Contains(output, key.(map[string]any)["secret"].(string)) {
			t.Fatal("audit output leaked an enrollment key secret")
		}
	}
	filtered := admin.expect("GET", "/api/org/audit?action=enrollment_key_issued", nil, "", 200)["events"].([]any)
	if len(filtered) != 100 {
		t.Fatalf("filtered page returned %d events", len(filtered))
	}
	for _, value := range filtered {
		if value.(map[string]any)["action"] != "enrollment_key_issued" {
			t.Fatal("action filter returned another action")
		}
	}
	for _, value := range adminB.expect("GET", "/api/org/audit", nil, "", 200)["events"].([]any) {
		event := value.(map[string]any)
		if seen[event["id"].(string)] || event["target_id"] == orgs[0] {
			t.Fatal("organization B can read organization A audit events")
		}
	}
	admin.expect("GET", "/api/org/audit?action=drop_tables", nil, "", 400)
	admin.expect("GET", "/api/org/audit?before=2026-10-18T00:00:00Z", nil, "", 400)
	admin.expect("GET", "/api/org/audit?before=yesterday&before_id="+strings.Repeat("a", 64), nil, "", 400)
}
