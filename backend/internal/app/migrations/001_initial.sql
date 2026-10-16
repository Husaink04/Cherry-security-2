CREATE TABLE organizations (
 id text PRIMARY KEY, name text NOT NULL CHECK(length(name) BETWEEN 1 AND 120),
 timezone text NOT NULL, idle_seconds integer NOT NULL DEFAULT 300 CHECK(idle_seconds BETWEEN 60 AND 3600),
 raw_retention_days integer NOT NULL DEFAULT 7 CHECK(raw_retention_days BETWEEN 1 AND 90),
 summary_retention_days integer NOT NULL DEFAULT 30 CHECK(summary_retention_days BETWEEN 1 AND 365),
 collection_schedule jsonb NOT NULL DEFAULT '{"days":[1,2,3,4,5],"start":"09:00","end":"18:00","unrestricted":false}',
 created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE accounts (
 id text PRIMARY KEY, email text NOT NULL UNIQUE, password_hash text NOT NULL,
 role text NOT NULL CHECK(role IN ('product_owner','org_admin','org_viewer')),
 organization_id text REFERENCES organizations(id),
 CHECK((role='product_owner' AND organization_id IS NULL) OR (role<>'product_owner' AND organization_id IS NOT NULL))
);
CREATE TABLE sessions (token_hash text PRIMARY KEY, account_id text NOT NULL REFERENCES accounts(id), csrf_hash text NOT NULL, expires_at timestamptz NOT NULL);
CREATE INDEX sessions_expiry ON sessions(expires_at);
CREATE TABLE enrollment_keys (
 id text PRIMARY KEY, organization_id text NOT NULL REFERENCES organizations(id),
 secret_hash text NOT NULL UNIQUE, issuer_id text NOT NULL REFERENCES accounts(id),
 created_at timestamptz NOT NULL DEFAULT now(), expires_at timestamptz NOT NULL,
 used_at timestamptz, revoked_at timestamptz, device_id text
);
CREATE TABLE devices (
 id text PRIMARY KEY, organization_id text NOT NULL REFERENCES organizations(id),
 hostname text NOT NULL, employee_id text NOT NULL DEFAULT '', os text NOT NULL, agent_version text NOT NULL,
 simulated boolean NOT NULL, token_hash text NOT NULL UNIQUE, revoked_at timestamptz,
 created_at timestamptz NOT NULL DEFAULT now(), last_contact timestamptz, helper_status text NOT NULL DEFAULT 'unknown', extension_status text NOT NULL DEFAULT 'missing'
);
ALTER TABLE enrollment_keys ADD FOREIGN KEY(device_id) REFERENCES devices(id);
CREATE INDEX devices_org ON devices(organization_id);
CREATE TABLE events (
 device_id text NOT NULL REFERENCES devices(id), event_id text NOT NULL,
 session_id text NOT NULL, sequence bigint NOT NULL CHECK(sequence>=0),
 observed_at timestamptz NOT NULL, received_at timestamptz NOT NULL DEFAULT now(),
 kind text NOT NULL CHECK(kind IN ('application','browser','idle','locked','gap','service')),
 starts_at timestamptz, ends_at timestamptz, payload jsonb NOT NULL, content_hash text NOT NULL,
 PRIMARY KEY(device_id,event_id)
);
CREATE INDEX events_device_time ON events(device_id,observed_at);
CREATE INDEX events_overlap ON events(device_id,session_id,starts_at,ends_at) WHERE kind IN ('application','idle','locked','gap');
CREATE TABLE daily_summaries (
 device_id text NOT NULL REFERENCES devices(id), day date NOT NULL, timezone text NOT NULL,
 kind text NOT NULL, label text NOT NULL, seconds bigint NOT NULL CHECK(seconds>=0),
 PRIMARY KEY(device_id,day,timezone,kind,label)
);
CREATE TABLE audit_events (
 id text PRIMARY KEY, organization_id text REFERENCES organizations(id), actor_id text,
 action text NOT NULL, target_id text NOT NULL, detail jsonb NOT NULL DEFAULT '{}', created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX audit_org_time ON audit_events(organization_id,created_at);
