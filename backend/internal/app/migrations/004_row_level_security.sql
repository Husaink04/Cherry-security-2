-- Row-level security is a second tenant boundary beneath the application's organization filters.
-- Each transaction declares app.scope, plus app.organization_id for tenant work, with set_config(..., true).
-- A transaction that declares nothing matches no policy, so it reads and changes nothing.
-- Superusers and BYPASSRLS roles skip policies; the API refuses to start as either.

-- Pin this migration's objects and the SECURITY DEFINER search_path to the migrated schema.
SELECT set_config('search_path', quote_ident(current_schema()) || ', pg_temp', true);

DO $$
BEGIN
 IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'cherry_auth' AND (rolcanlogin OR rolsuper)) THEN
  RAISE EXCEPTION 'cherry_auth must be a NOLOGIN, non-superuser role';
 END IF;
 IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'cherry_auth') THEN
  -- Owns only the pre-tenant lookup functions below; nobody logs in as or inherits from it.
  CREATE ROLE cherry_auth NOLOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE BYPASSRLS;
 END IF;
 EXECUTE format('GRANT USAGE ON SCHEMA %I TO cherry_auth', current_schema());
END $$;
GRANT SELECT ON accounts, sessions, devices, enrollment_keys TO cherry_auth;
-- SELECT ... FOR UPDATE needs UPDATE on one column; the function never updates.
GRANT UPDATE (used_at) ON enrollment_keys TO cherry_auth;

CREATE FUNCTION rls_scope() RETURNS text LANGUAGE sql STABLE
 RETURN coalesce(current_setting('app.scope', true), '');
-- The caller's organization, only inside a tenant or per-organization retention transaction.
CREATE FUNCTION rls_tenant() RETURNS text LANGUAGE sql STABLE
 RETURN CASE WHEN current_setting('app.scope', true) IN ('tenant', 'retention') THEN nullif(current_setting('app.organization_id', true), '') END;

ALTER TABLE organizations ENABLE ROW LEVEL SECURITY;
ALTER TABLE organizations FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_read ON organizations FOR SELECT USING (id = rls_tenant());
CREATE POLICY tenant_update ON organizations FOR UPDATE USING (id = rls_tenant()) WITH CHECK (id = rls_tenant());
CREATE POLICY owner_read ON organizations FOR SELECT USING (rls_scope() = 'owner');
CREATE POLICY owner_create ON organizations FOR INSERT WITH CHECK (rls_scope() = 'owner');
CREATE POLICY retention_read ON organizations FOR SELECT USING (rls_scope() = 'retention');
CREATE POLICY retention_update ON organizations FOR UPDATE USING (rls_scope() = 'retention') WITH CHECK (rls_scope() = 'retention');

ALTER TABLE accounts ENABLE ROW LEVEL SECURITY;
ALTER TABLE accounts FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_read ON accounts FOR SELECT USING (organization_id = rls_tenant());
CREATE POLICY owner_read ON accounts FOR SELECT USING (rls_scope() = 'owner' AND role = 'org_admin');
CREATE POLICY owner_create ON accounts FOR INSERT WITH CHECK (rls_scope() = 'owner' AND role = 'org_admin' AND organization_id IS NOT NULL);
CREATE POLICY bootstrap_read ON accounts FOR SELECT USING (rls_scope() = 'bootstrap' AND role = 'product_owner');
CREATE POLICY bootstrap_create ON accounts FOR INSERT WITH CHECK (rls_scope() = 'bootstrap' AND role = 'product_owner');
-- Bootstrap's existence check sees only what policies allow; this index keeps one Product Owner regardless.
CREATE UNIQUE INDEX accounts_single_product_owner ON accounts (role) WHERE role = 'product_owner';

ALTER TABLE devices ENABLE ROW LEVEL SECURITY;
ALTER TABLE devices FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_read ON devices FOR SELECT USING (organization_id = rls_tenant());
CREATE POLICY tenant_create ON devices FOR INSERT WITH CHECK (organization_id = rls_tenant());
CREATE POLICY tenant_update ON devices FOR UPDATE USING (organization_id = rls_tenant()) WITH CHECK (organization_id = rls_tenant());
CREATE POLICY owner_read ON devices FOR SELECT USING (rls_scope() = 'owner');

ALTER TABLE enrollment_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE enrollment_keys FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_read ON enrollment_keys FOR SELECT USING (organization_id = rls_tenant());
-- A tenant transaction may only mark one of its unused keys as redeemed by a device.
CREATE POLICY tenant_redeem ON enrollment_keys FOR UPDATE USING (organization_id = rls_tenant() AND used_at IS NULL)
 WITH CHECK (organization_id = rls_tenant() AND used_at IS NOT NULL AND device_id IS NOT NULL);
CREATE POLICY owner_read ON enrollment_keys FOR SELECT USING (rls_scope() = 'owner');
CREATE POLICY owner_create ON enrollment_keys FOR INSERT WITH CHECK (rls_scope() = 'owner');
CREATE POLICY owner_revoke ON enrollment_keys FOR UPDATE USING (rls_scope() = 'owner') WITH CHECK (rls_scope() = 'owner');

ALTER TABLE events ENABLE ROW LEVEL SECURITY;
ALTER TABLE events FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_read ON events FOR SELECT USING (EXISTS (SELECT 1 FROM devices d WHERE d.id = events.device_id AND d.organization_id = rls_tenant()));
CREATE POLICY tenant_create ON events FOR INSERT WITH CHECK (EXISTS (SELECT 1 FROM devices d WHERE d.id = events.device_id AND d.organization_id = rls_tenant()));
CREATE POLICY retention_delete ON events FOR DELETE USING (rls_scope() = 'retention' AND EXISTS (SELECT 1 FROM devices d WHERE d.id = events.device_id AND d.organization_id = rls_tenant()));

ALTER TABLE daily_summaries ENABLE ROW LEVEL SECURITY;
ALTER TABLE daily_summaries FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_read ON daily_summaries FOR SELECT USING (EXISTS (SELECT 1 FROM devices d WHERE d.id = daily_summaries.device_id AND d.organization_id = rls_tenant()));
CREATE POLICY tenant_create ON daily_summaries FOR INSERT WITH CHECK (EXISTS (SELECT 1 FROM devices d WHERE d.id = daily_summaries.device_id AND d.organization_id = rls_tenant()));
CREATE POLICY tenant_accumulate ON daily_summaries FOR UPDATE
 USING (EXISTS (SELECT 1 FROM devices d WHERE d.id = daily_summaries.device_id AND d.organization_id = rls_tenant()))
 WITH CHECK (EXISTS (SELECT 1 FROM devices d WHERE d.id = daily_summaries.device_id AND d.organization_id = rls_tenant()));
CREATE POLICY retention_delete ON daily_summaries FOR DELETE USING (rls_scope() = 'retention' AND EXISTS (SELECT 1 FROM devices d WHERE d.id = daily_summaries.device_id AND d.organization_id = rls_tenant()));

-- Audit rows are append-only for the API; only retention deletes them and nothing updates them.
ALTER TABLE audit_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_events FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_read ON audit_events FOR SELECT USING (organization_id = rls_tenant());
CREATE POLICY tenant_append ON audit_events FOR INSERT WITH CHECK (organization_id = rls_tenant());
CREATE POLICY owner_append ON audit_events FOR INSERT WITH CHECK (rls_scope() = 'owner');
CREATE POLICY login_failure_append ON audit_events FOR INSERT WITH CHECK (rls_scope() = 'login' AND actor_id IS NULL AND action = 'login_failed');
CREATE POLICY retention_read ON audit_events FOR SELECT USING (rls_scope() = 'retention');
CREATE POLICY retention_delete ON audit_events FOR DELETE USING (rls_scope() = 'retention');

-- Pre-tenant lookups. Each returns at most the row matching one secret hash, email, or ID.
CREATE FUNCTION auth_login(p_email text)
 RETURNS TABLE (account_id text, password_hash text, account_role text, organization_id text)
 LANGUAGE sql STABLE SECURITY DEFINER SET search_path FROM CURRENT
 AS $$ SELECT a.id, a.password_hash, a.role, coalesce(a.organization_id, '') FROM accounts a WHERE a.email = p_email $$;
CREATE FUNCTION auth_session(p_token_hash text)
 RETURNS TABLE (account_id text, account_role text, organization_id text, csrf_hash text)
 LANGUAGE sql STABLE SECURITY DEFINER SET search_path FROM CURRENT
 AS $$ SELECT a.id, a.role, coalesce(a.organization_id, ''), s.csrf_hash FROM sessions s JOIN accounts a ON a.id = s.account_id WHERE s.token_hash = p_token_hash AND s.expires_at > now() $$;
CREATE FUNCTION auth_device(p_token_hash text)
 RETURNS TABLE (device_id text, organization_id text)
 LANGUAGE sql STABLE SECURITY DEFINER SET search_path FROM CURRENT
 AS $$ SELECT d.id, d.organization_id FROM devices d WHERE d.token_hash = p_token_hash AND d.revoked_at IS NULL $$;
CREATE FUNCTION claim_enrollment_key(p_secret_hash text)
 RETURNS TABLE (key_id text, organization_id text)
 LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path FROM CURRENT
 AS $$ SELECT k.id, k.organization_id FROM enrollment_keys k WHERE k.secret_hash = p_secret_hash AND k.used_at IS NULL AND k.revoked_at IS NULL AND k.expires_at > now() FOR UPDATE $$;
CREATE FUNCTION is_product_owner(p_account_id text) RETURNS boolean
 LANGUAGE sql STABLE SECURITY DEFINER SET search_path FROM CURRENT
 AS $$ SELECT EXISTS (SELECT 1 FROM accounts a WHERE a.id = p_account_id AND a.role = 'product_owner') $$;
ALTER FUNCTION auth_login(text) OWNER TO cherry_auth;
ALTER FUNCTION auth_session(text) OWNER TO cherry_auth;
ALTER FUNCTION auth_device(text) OWNER TO cherry_auth;
ALTER FUNCTION claim_enrollment_key(text) OWNER TO cherry_auth;
ALTER FUNCTION is_product_owner(text) OWNER TO cherry_auth;
REVOKE ALL ON FUNCTION auth_login(text), auth_session(text), auth_device(text), claim_enrollment_key(text), is_product_owner(text) FROM PUBLIC;
