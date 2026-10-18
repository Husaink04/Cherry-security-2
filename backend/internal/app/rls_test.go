package app

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

type rowQuerier interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}

// TestRowLevelSecurityWithoutTenantFilters runs queries whose organization filters were
// deliberately removed, so only the migration 004 policies keep the other tenant's rows out.
func TestRowLevelSecurityWithoutTenantFilters(t *testing.T) {
	fixture, runtimeDB, server, owner, _ := setupIntegrationPools(t)
	ctx := context.Background()
	anonymous := &testClient{t: t, client: server.Client(), base: server.URL}
	start := time.Now().UTC().Truncate(time.Hour).Add(-time.Hour)
	orgs, devices := map[string]string{}, map[string]string{}
	for _, name := range []string{"alpha", "beta"} {
		created := owner.expect("POST", "/api/owner/organizations", map[string]any{"name": "RLS " + name, "timezone": "UTC", "admin": map[string]any{"email": name + "-rls@example.test", "password": "Strong-rls-password-2026!"}, "key_count": 2}, "", 201)
		orgs[name] = created["id"].(string)
		key := created["keys"].([]any)[0].(map[string]any)
		enrolled := anonymous.expect("POST", "/api/agent/enroll", map[string]any{"enrollment_key": key["secret"], "hostname": name + "-rls-host", "os": "Windows fixture", "agent_version": "m1", "simulated": true}, "", 201)
		devices[name] = enrolled["device_id"].(string)
		event := map[string]any{"event_id": "rls-app", "session_id": "session", "sequence": 1, "observed_at": start.Add(300 * time.Second).Format(time.RFC3339), "kind": "application", "payload": map[string]any{"app": name + "-rls.exe", "start": start.Format(time.RFC3339), "end": start.Add(300 * time.Second).Format(time.RFC3339)}}
		anonymous.expect("POST", "/api/agent/events", map[string]any{"schema_version": 1, "events": []any{event}}, enrolled["device_token"].(string), 200)
	}
	alpha, beta := orgs["alpha"], orgs["beta"]
	count := func(q rowQuerier, query string, args ...any) int64 {
		t.Helper()
		var n int64
		if err := q.QueryRow(ctx, query, args...).Scan(&n); err != nil {
			t.Fatalf("%s: %v", query, err)
		}
		return n
	}
	scoped := func(s dbScope, fn func(pgx.Tx)) {
		t.Helper()
		tx, err := beginScoped(ctx, runtimeDB, s)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(ctx)
		fn(tx)
	}
	tables := []struct{ name, own string }{
		{"organizations", "id=$1"},
		{"accounts", "organization_id=$1"},
		{"devices", "organization_id=$1"},
		{"enrollment_keys", "organization_id=$1"},
		{"audit_events", "organization_id=$1"},
		{"events", "device_id IN (SELECT id FROM devices WHERE organization_id=$1)"},
		{"daily_summaries", "device_id IN (SELECT id FROM devices WHERE organization_id=$1)"},
	}
	for _, table := range tables {
		own := count(fixture, "SELECT count(*) FROM "+table.name+" WHERE "+table.own, alpha)
		all := count(fixture, "SELECT count(*) FROM "+table.name)
		if own == 0 || all <= own {
			t.Fatalf("%s fixture needs rows in both tenants: own=%d all=%d", table.name, own, all)
		}
		scoped(tenantScope(alpha), func(tx pgx.Tx) {
			if got := count(tx, "SELECT count(*) FROM "+table.name); got != own {
				t.Fatalf("unfiltered %s returned %d rows to alpha; alpha owns %d", table.name, got, own)
			}
		})
		// Without a declared scope, or with only the login scope, every tenant row stays hidden.
		if got := count(runtimeDB, "SELECT count(*) FROM "+table.name); got != 0 {
			t.Fatalf("unscoped %s query returned %d rows", table.name, got)
		}
		scoped(loginScope, func(tx pgx.Tx) {
			if got := count(tx, "SELECT count(*) FROM "+table.name); got != 0 {
				t.Fatalf("login scope read %d %s rows", got, table.name)
			}
		})
	}
	// Production queries with their organization predicate deleted still return only alpha's rows.
	scoped(tenantScope(alpha), func(tx pgx.Tx) {
		var results []any
		for _, query := range []string{
			"SELECT " + deviceJSON + " FROM devices d ORDER BY d.created_at DESC LIMIT 100",
			"SELECT jsonb_build_object('device_id',d.id,'hostname',d.hostname,'label',s.label,'seconds',s.seconds) FROM daily_summaries s JOIN devices d ON d.id=s.device_id",
			"SELECT jsonb_build_object('event_id',e.event_id,'payload',e.payload) FROM events e",
			"SELECT jsonb_build_object('target_id',e.target_id) FROM audit_events e",
		} {
			items, err := jsonRows(ctx, tx, query)
			if err != nil {
				t.Fatal(err)
			}
			results = append(results, items)
		}
		data, _ := json.Marshal(results)
		for _, marker := range []string{beta, devices["beta"], "beta-rls-host", "beta-rls.exe"} {
			if strings.Contains(string(data), marker) {
				t.Fatalf("unfiltered production query exposed beta marker %q", marker)
			}
		}
		if !strings.Contains(string(data), "alpha-rls.exe") {
			t.Fatal("alpha lost its own rows, so the check above proves nothing")
		}
	})
	denied := func(s dbScope, query string, args ...any) {
		t.Helper()
		scoped(s, func(tx pgx.Tx) {
			var pg *pgconn.PgError
			if _, err := tx.Exec(ctx, query, args...); !errors.As(err, &pg) || pg.Code != "42501" {
				t.Fatalf("%q was not refused by row-level security: %v", query, err)
			}
		})
	}
	affected := func(s dbScope, query string, want int64) {
		t.Helper()
		scoped(s, func(tx pgx.Tx) {
			tag, err := tx.Exec(ctx, query)
			if err != nil || tag.RowsAffected() != want {
				t.Fatalf("%q affected %d rows (%v); want %d", query, tag.RowsAffected(), err, want)
			}
		})
	}
	// Writes cannot create rows in, or move rows into, another tenant.
	denied(tenantScope(alpha), "INSERT INTO devices(id,organization_id,hostname,os,agent_version,simulated,token_hash) VALUES($1,$2,'forged','Windows','m1',true,$3)", RandomToken(), beta, digest(RandomToken()))
	denied(tenantScope(alpha), "UPDATE devices SET organization_id=$1", beta)
	denied(tenantScope(alpha), "INSERT INTO audit_events(id,organization_id,action,target_id) VALUES($1,$2,'settings_updated',$2)", RandomToken(), beta)
	denied(tenantScope(alpha), "INSERT INTO events(device_id,event_id,session_id,sequence,observed_at,kind,payload,content_hash) VALUES($1,'forged','session',1,now(),'service','{}','hash')", devices["beta"])
	denied(ownerScope, "INSERT INTO accounts(id,email,password_hash,role) VALUES($1,'second-owner@example.test','x','product_owner')", RandomToken())
	denied(loginScope, "INSERT INTO audit_events(id,organization_id,actor_id,action,target_id) VALUES($1,$2,$3,'login',$3)", RandomToken(), alpha, RandomToken())
	// Unfiltered writes reach only the caller's rows; activity and audit rows cannot be erased or rewritten outside retention.
	affected(tenantScope(alpha), "UPDATE devices SET employee_id='unfiltered'", 1)
	affected(tenantScope(alpha), "UPDATE organizations SET name='unfiltered'", 1)
	affected(tenantScope(alpha), "DELETE FROM events", 0)
	affected(tenantScope(alpha), "DELETE FROM daily_summaries", 0)
	affected(tenantScope(alpha), "UPDATE audit_events SET action='login'", 0)
	affected(tenantScope(alpha), "DELETE FROM audit_events", 0)
	affected(ownerScope, "DELETE FROM events", 0)
	// The Product Owner scope provisions tenants but never reads activity or audit data.
	scoped(ownerScope, func(tx pgx.Tx) {
		for _, table := range []string{"events", "daily_summaries", "audit_events"} {
			if got := count(tx, "SELECT count(*) FROM "+table); got != 0 {
				t.Fatalf("Product Owner scope read %d %s rows", got, table)
			}
		}
		if got := count(tx, "SELECT count(*) FROM accounts WHERE role<>'org_admin'"); got != 0 {
			t.Fatalf("Product Owner scope read %d non-administrator accounts", got)
		}
	})
	// A tenant ID declared under another scope grants nothing, and Go refuses malformed scopes.
	spoof, err := runtimeDB.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = spoof.Exec(ctx, "SELECT set_config('app.scope','owner',true),set_config('app.organization_id',$1,true)", alpha); err != nil {
		t.Fatal(err)
	}
	if got := count(spoof, "SELECT count(*) FROM events"); got != 0 {
		t.Fatalf("organization ID under the owner scope exposed %d events", got)
	}
	if err = spoof.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	for _, invalid := range []dbScope{tenantScope(""), {name: "owner", organization: alpha}, {name: "superuser"}} {
		if setScope(ctx, nil, invalid) == nil {
			t.Fatalf("invalid scope %+v accepted", invalid)
		}
	}
	// Transaction-local settings must not survive on a pooled connection.
	conn, err := runtimeDB.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Release()
	tx, err := conn.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err = setScope(ctx, tx, tenantScope(alpha)); err != nil {
		t.Fatal(err)
	}
	if got := count(tx, "SELECT count(*) FROM devices"); got != 1 {
		t.Fatalf("alpha scope saw %d devices", got)
	}
	if err = tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if got := count(conn, "SELECT count(*) FROM devices"); got != 0 {
		t.Fatalf("tenant scope outlived its transaction on a pooled connection: %d rows", got)
	}
	// Pre-tenant lookups return only an exact match, and roles that skip policies are refused.
	if got := count(runtimeDB, "SELECT count(*) FROM auth_device($1)", digest("not-a-device-token")); got != 0 {
		t.Fatalf("device lookup matched %d devices for an unknown token", got)
	}
	if err = BootstrapOwner(ctx, runtimeDB, "second-owner@example.test", "Strong-second-owner-2026!"); err == nil {
		t.Fatal("bootstrap under row-level security created a second Product Owner")
	}
	if err = CheckRuntimeRole(ctx, runtimeDB); err != nil {
		t.Fatal(err)
	}
	if CheckRuntimeRole(ctx, fixture) == nil {
		t.Fatal("a role that bypasses row-level security must be refused")
	}
	// Retention runs under its own scopes and keeps current activity.
	if err = Cleanup(ctx, runtimeDB, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	if got := count(fixture, "SELECT count(*) FROM events"); got != 2 {
		t.Fatalf("cleanup under row-level security left %d of 2 current events", got)
	}
}
