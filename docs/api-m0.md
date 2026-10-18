# CherrySecurity M0 API contract

All routes are prefixed `/api`. Responses are JSON with `Cache-Control: no-store`. Error shape: `{ "error": "safe description" }`. Validation errors do not echo submitted secrets or bodies. Unknown request fields are rejected. Normal JSON bodies have a 1 MiB limit.

The initial deployment is accessible only through loopback SSH forwarding. Browser/API have one origin. HTTP cookies are permitted only for that local development origin; a remote production deployment must use HTTPS and secure cookies.

## Sessions and roles

| Method and route | Access | Behavior |
| --- | --- | --- |
| GET `/healthz` | Public | Process liveness, independent of database |
| GET `/readyz` | Public | M0 deployed schema 2; M1 source requires schema 3 after its approved migration |
| POST `/auth/login` | Public, exact Origin required | `{email,password}`; returns role, organization ID, and CSRF token; sets HttpOnly SameSite=Strict cookie |
| GET `/auth/me` | Session | Returns role, organization ID, and session-bound CSRF token without rotating the session |
| POST `/auth/logout` | Session + CSRF | Deletes the server session and expires its cookie |

Session lifespan is eight hours. Passwords are bcrypt-hashed at cost 12; initial passwords must contain 14–72 bytes. Each API process limits login attempts to 5 per 15 minutes per account email (known or unknown, so lockouts do not reveal which accounts exist), 20 per minute per client address, and 180 per minute overall to bound password-hashing CPU; exceeding a limit returns 429 with `Retry-After`, and a successful login resets the account counter. The client address comes from `X-Real-IP` only when `TRUST_PROXY_HEADER=true`, which Compose sets because the bundled nginx proxy overwrites that header; never enable it when the API is reachable without that proxy. Failed password checks are audited as `login_failed` with the account ID when known, never the submitted email or password. Login, accounts, sessions, and all API data persist in PostgreSQL.

Every authenticated browser write requires the exact configured `Origin` and `X-CSRF-Token`. Roles are `product_owner`, `org_admin`, `org_viewer`. Owner provisioning authority does not confer activity access. Device bearer tokens never authenticate browser organization routes.

## Product Owner provisioning

| Method and route | Request / result |
| --- | --- |
| GET `/owner/organizations?q=...` | Up to 100 most recent organizations, optionally filtered by a case-insensitive literal name substring (at most 120 bytes), each with `admin_count`, `active_device_count`, and `unused_key_count` provisioning counts only |
| POST `/owner/organizations` | `{name,timezone,admin?:{email,password},key_count?}` with `key_count` 0–100; returns `{id,admin_id?,keys?}` with key secrets once; IANA timezone validated; organization, first administrator, and keys are created in one transaction, so any failure (for example a duplicate administrator email, 409) creates nothing |
| POST `/owner/organizations/{id}/admins` | `{email,password}`; creates an organization administrator |
| POST `/owner/organizations/{id}/keys` | `{count}` with 1–100; returns `keys:[{id,secret,expires_at}]` once |
| GET `/owner/organizations/{id}/keys` | Metadata only, up to 500 most recent keys |
| POST `/owner/keys/{id}/revoke` | Revokes an unused key; cannot revoke an already-used key |

Keys have 256 bits of random entropy, expire after 24 hours, and are hashed in storage. One key enrolls one endpoint. A transaction serializes redemption and device creation. Lost successful enrollment responses require an explicitly issued replacement key; M0 does not recover a lost device secret.

## Endpoint contract

POST `/agent/enroll`:

```json
{
  "enrollment_key": "<secret supplied securely>",
  "hostname": "SIMULATED-WINDOWS-M0",
  "os": "Windows simulated fixture",
  "agent_version": "m0-simulator",
  "simulated": true
}
```

Returns `{device_id,device_token}` once. The organization comes exclusively from the key. Deployed M0 rejects real/non-simulated enrollment; M1 source accepts and persists either explicit simulated state. Used, expired, and revoked keys return 401.

M1 adds device-authenticated `GET /agent/policy`: schema version 1, stable policy hash, server UTC time, IANA timezone, idle seconds, collection schedule, raw retention and irreversible ingestion floor, upload interval 60 seconds, validity 86400 seconds. M1 native event schema 2 supports typed gap reasons while preserving schema 1 JSON/replay compatibility. Native heartbeat schema 2 reports collection/policy/queue/error/loss health; unsupported fields and counter rollback are rejected. Loss epochs are retained up to 64 per device; exceeding that bound requires explicit recovery. These source changes are not live until the separate rollout approval.

M1 adds administrator-only `PUT /org/devices/{id}/employee` with `{employee_id}` (trimmed, at most 120 bytes). Assignment is tenant scoped and audited; an empty value unassigns. Product Owner and viewer roles cannot assign employee labels.

After enrollment use `Authorization: Bearer <device_token>` for:

- POST `/agent/heartbeat`: `{helper,extension}` with collector states `healthy`, `missing`, `unknown`, `simulated`, or `stopped`.
- POST `/agent/events`: `{schema_version:1,events:[...]}` containing 1–500 typed events. The response contains `accepted_event_ids` only after the transaction commits.

Each event has `event_id`, `session_id`, nonnegative `sequence`, UTC `observed_at`, `kind`, and `payload`. Events must fall within the organization's raw-retention window and at most five minutes in the future. Activity intervals must be positive, no longer than 24 hours, and end no later than the observation time.

| Kind | Payload |
| --- | --- |
| `application` | `{start,end,app}`; application basename, no path/window title |
| `browser` | `{start,end,hostname}`; normalized hostname only, no URL/title/content |
| `idle`, `locked`, `gap` | `{start,end}` only |
| `service` | `{service,state,startup_type}`; no activity interval |

Service state accepts running, stopped, paused, start_pending, stop_pending, continue_pending, pause_pending, or unknown. Startup type accepts automatic, manual, disabled, or unknown.

Identical event-ID retries are acknowledged without changing totals. A different payload for an existing device/event ID returns 409. Invalid batches roll back completely. Application/idle/locked/gap intervals cannot overlap; browser intervals are separate and cannot overlap each other. Report browser seconds separately; never add them to foreground application time. Actual foreground/browser correlation is a collector requirement in M2, not proof established by synthetic M0 input.

## Organization queries and settings

| Method and route | Access / result |
| --- | --- |
| GET `/org/devices` | Admin/viewer; up to 100 most recent devices |
| GET `/org/devices/{id}` | Admin/viewer; scoped device, up to 100 latest events, coverage, sequence-gap count |
| GET `/org/devices/{id}/services` | Admin/viewer; up to 500 latest observed service states |
| POST `/org/devices/{id}/revoke` | Admin only; future heartbeat/ingestion rejected |
| GET `/org/keys` | Admin only; organization-bound key metadata only (viewers do not enroll devices) |
| GET `/org/reports/daily?date=YYYY-MM-DD&device_id=...` | Admin/viewer; organization-local date, optional device filter, separate duration totals and breakdown |
| GET `/org/settings` | Admin/viewer; organization name/timezone, idle threshold, collection schedule, retention |
| PUT `/org/settings` | Admin only; validated settings and audit event |
| GET `/org/audit?action=...&before=...&before_id=...` | Admin only; this organization's audit events, newest first, 100 per page with `has_more`; optional `action` from the fixed list; page with the last event's `created_at` and `id` together |

Audit events show the actor as an email only for accounts in the same organization, `Product Owner` for the platform owner (never their email), `device <hostname>` for the organization's devices, and `system` or `unknown` otherwise. Targets resolve the same way. Unknown action filters and malformed cursors return 400.

Unknown or cross-organization device IDs return 404. Settings writes include `idle_seconds` (60–3600), `raw_retention_days` (1–90), `summary_retention_days` (at least raw retention, at most 365), and `collection_schedule:{days,start,end,unrestricted}`. Weekdays use Sunday=0. Scheduled windows must end after start on the same day; overnight schedules are not yet supported. Timezone is selected at organization creation and immutable in M0 to preserve existing daily summaries.

Reports return UTC observation/update timestamps and organization reporting timezone. Durations split correctly at local midnight, including offset transitions. Missing data is labeled unknown/partial rather than inferred as idle. Heartbeat connectivity is online under three minutes, stale from three to five minutes, and offline after five; revoked and never-seen devices have explicit states. Collector health is independent of connectivity.

Daily reports return at most 1,000 breakdown rows with an explicit truncation indicator. Duration totals aggregate all matching rows independently of that limit. This is an M0 bound, not a supported commercial capacity or pagination guarantee. Multi-user device concurrency and employee directory/filtering are later work; M0 filters by device.

## Storage and operations

Raw observations default to seven-day retention; summaries default to 30 days. Hourly cleanup applies each retention independently, removes expired sessions, and expires audit records after 90 days. Observations arriving older than raw retention are rejected explicitly, not reassigned to today. Existing summaries survive raw-event expiry. Cleanup advances a persistent ingestion watermark before deleting deduplication evidence; increasing retention cannot reopen expired history and double-count old replays.

API runtime database access uses non-superuser `cherryapp`; migrations and local restore use `cherryowner`. PostgreSQL row-level security (migration 004) is a second tenant boundary: every API transaction declares its scope, the API refuses to start as a role that bypasses row-level security, and pre-tenant lookups (login, session, device token, enrollment key) use narrow functions owned by the NOLOGIN `cherry_auth` role. No database port is published. Secrets reside in Kali's ignored, mode-600 `.env` and are not printed in setup logs. Avoid sharing `docker compose config` output without `--quiet`: it contains resolved secrets.

The separate `browser-test` profile uses the dedicated `_test` database, synthetic accounts, a separate network, and loopback port 8082. It does not seed or replace the real Product Owner. Private fixture credentials are ignored by Git and must not be published with test artifacts.
