# CherrySecurity M1 Windows Agent Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans for inline implementation, or superpowers:subagent-driven-development only if the user chooses delegated execution. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Collect real Windows foreground/application and service observations with a managed, transparent agent, durable bounded delivery, and verified organization-scoped reporting.

**Architecture:** A LocalService Go service owns policy, credentials, SQLite, inventory, and HTTPS; an unelevated session helper observes the selected desktop and exposes tray status through authenticated local IPC. Extend existing M0 enrollment, telemetry, and React reporting without removing simulator compatibility. Deploy only through separately approved resource batches.

**Tech Stack:** Go 1.27.2 toolchain, Go standard HTTP/TLS/JSON, `golang.org/x/sys v0.49.0`, `github.com/Microsoft/go-winio v0.6.4`, `modernc.org/sqlite v1.60.1`, existing PostgreSQL/React/TypeScript/Compose stack. Versions were checked against the Go module proxy on 2026-10-16; recheck advisories and verify module sums when obtaining dependencies. Pin transitive versions in the new agent module, following the SQLite module's own dependency requirements. Driver selection is conditional on actual memory and disk measurements, not assumed performance.

**Spec:** [M1 Windows agent design](../specs/2026-10-16-m1-windows-agent-design.md), revision `57ed14b`, approved by the user after the managed-service amendment. This plan does not change that design. Organization-owner-only stop authorization is future design work, not an M1 guarantee or implementation task.

## Global constraints

- Use the exact brand spelling **CherrySecurity**, **CherrySecurity Agent**, and **CherrySecurity Console**.
- M1 supports the reference Windows 11 Pro x64 machine and one selected local interactive user. Do not claim concurrent-session support.
- The employee-facing interface has no stop/uninstall controls; administrator management is separate.
- No kernel driver, process hiding, Task Manager evasion, or anti-uninstall mechanism is introduced.
- An authorized administrator's explicit stop or uninstall must remain effective and must not be reversed by a helper, watchdog, task, or automatic reinstallation.
- No process command lines, window titles, documents, input contents, screenshots, clipboard, audio, or video are collected.
- Browser extensions remain M2. Do not infer browser-domain activity from process names.
- Service/helper combined private bytes target: at most 50 MiB; average CPU target: below 1% of total machine CPU over eight hours. Both remain unmeasured until acceptance.
- Queue cap including journal: 50 MiB; database cap: 40 MiB; combined diagnostic logs cap: 10 MiB. Crash checkpoint loss window: at most five seconds.
- Upload default: 60 seconds, constrained to 60–300 seconds; at most 500 events and less than 1 MiB serialized per batch; one upload in flight, 10-second request timeout, jittered exponential backoff from two seconds to five minutes.
- Policy refresh: 60 seconds; offline validity: 24 hours; expired/missing policy stops activity collection. Idle threshold remains organization-controlled, 60–3600 seconds, initially 300 seconds.
- Keep TLS/SSH identity validation, parameterized SQL, tenant isolation, and versioned strict validation. OWASP Top 10:2025 is the verified risk baseline, not a certification.
- Use full filesystem paths in commands and user instructions; retain portable module imports/configuration and Windows known-folder discovery.
- Preserve existing database contents and unrelated services, tasks, containers, files, trust stores, and firewall rules. No global cleanup, OS-wide certificate trust, software installation, or VM resizing is part of source implementation.

## Approval and execution boundaries

This document is a proposal. Design approval permits writing this plan; it does not approve the implementation or the system changes below. Review this plan before starting any task.

| Batch | Exact intended write effects | Gate |
| --- | --- | --- |
| A — source and isolated automated checks | Create Git branch `m1` from the reviewed current HEAD in `D:\Cherry-security`; create/modify only the files listed in Tasks 1–8, lockfiles, and ignored test/build artifacts in `D:\Cherry-security\artifacts`; sync those sources to `/home/husain/cherrysecurity-m0`; build/test using dedicated tool containers/cache volumes and unique `_test` databases/schemas; create task commits and push branch `m1` to the existing repository | User reviews/approves this plan and Batch A before implementation |
| B — Kali rollout and TLS | Backup the existing application DB; apply additive migration 003; recreate only CherrySecurity API/web/ingress containers; create private CA/server certificate files under `/home/husain/cherrysecurity-m0/secrets/agent-tls`; bind only a verified NAT address on port 8443; add a scoped firewall rule only if needed and specifically approved | Present exact verified listener/source IPs, certificate paths, migration/backup commands, and affected containers for separate approval |
| C — Windows local installation | Create `C:\Program Files\CherrySecurity` and `C:\ProgramData\CherrySecurity` through known-folder equivalents, service `CherrySecurityAgent`, and task `CherrySecurity Session Helper`; scoped ACLs, recovery/startup configuration, hidden-prompt enrollment, start helper/service; create one harmless test service `CherrySecurityM1Test` only for service-observation acceptance | Present selected account SID, signed/unsigned build hashes, complete install actions and test-service scope; user approves elevation and installation |
| D — assisted endpoint acceptance | Controlled CherrySecurity process crashes/stops, helper termination, app/idle/lock/suspend checks, synthetic 30-minute transport outage, test-device revocation, and an eight-hour benchmark with bounded output files | Present test effects and schedule, obtain approval, and coordinate human unlock/resume/key entry; never disable the host's global network |

Batch A does not authorize modifying the real application database, opening a listener, changing a firewall, installing a service/task, or running real desktop collection. Never infer permission for B–D from source approval. If a batch needs another resource, describe it and obtain approval first.

## Review focus

1. A retry of a locally acknowledged helper message must not duplicate events after a pipe reconnect or service crash (Tasks 3–4).
2. A schedule or idle-threshold change while provisional activity exists must split the buffer at the applied policy boundary without retroactively broadening collection (Task 2).
3. An installed executable/data directory replaced by a reparse point must be rejected before elevated writes, preserving unrelated files (Task 6).
4. A service recreated with the same name or a missed removal notification must not appear continuously observed with an old state (Task 5).
5. An HTTP 401 from the configured, verified server must stop collection; a TLS error or intermediary error must not be mistaken for revocation or trigger re-enrollment (Task 3).

Each item below has a named test in its owning task. Do not replace negative/failure checks with tests that merely mirror implementation helpers.

## Files and interfaces

All filesystem entries in this plan are under explicit roots. Within `D:\Cherry-security\agent`, use a compact `internal/agent` package with feature-specific files and thin commands, following the existing backend style. Windows-specific adapters use `_windows.go`; deterministic policy/timeline/queue/client logic stays testable on Linux. Do not expose unused abstractions or build a general plugin system.

- Agent commands: `D:\Cherry-security\agent\cmd\service\main_windows.go`, `cmd\helper\main_windows.go`, `cmd\control\main_windows.go`.
- Core: `D:\Cherry-security\agent\internal\agent\protocol.go`, `policy.go`, `timeline.go`, `queue.go`, `client.go`, `runtime.go`, `logs.go`, corresponding `_test.go` files.
- Windows adapters: `D:\Cherry-security\agent\internal\agent\ipc_windows.go`, `credentials_windows.go`, `desktop_windows.go`, `services_windows.go`, `status_windows.go`, `install_windows.go`, corresponding `_windows_test.go` files.
- Module/build: `D:\Cherry-security\agent\go.mod`, `go.sum`, `.dockerignore`; existing `D:\Cherry-security\.gitignore`, `.dockerignore`, `compose.yaml`, `scripts\Sync-Kali.ps1`; new `scripts\test-agent.sh`, `build-agent.sh`, `Invoke-AgentAcceptance.ps1`, `Measure-Agent.ps1`, `prepare-agent-tls.py`; new `deploy\agent-nginx.conf`.
- Backend: existing `D:\Cherry-security\backend\internal\app\app.go`, `provisioning.go`, `telemetry.go`, `reports.go`, `database.go`; new `agent_policy.go`, `native_agent_test.go`, `migrations\003_native_agent.sql`.
- Console/tests: existing `D:\Cherry-security\web\src\organization.tsx`, `model.ts`, `style.css`, `model.test.ts`; new `device-health.tsx`, `device-health.test.tsx`, `D:\Cherry-security\web\e2e\m1.spec.ts`. Prefer extracting the new device-health section from the large existing organization component; no unrelated frontend rewrite.
- Handoff: new `D:\Cherry-security\docs\M1-WINDOWS-OPERATIONS.md`, `docs\testing\M1-LEDGER.md`, `docs\testing\m1-results.md`; update `D:\Cherry-security\docs\api-m0.md`, `M0-DEVELOPMENT.md`, `TEAM-ONBOARDING.md`, `KALI-SETUP.md`, and root `README.md` only where behavior/status changes.

Module boundaries use mirrored, explicitly tested wire types rather than a new shared backend dependency. The agent never imports the server implementation.

## Task 1 — Real-device enrollment, policy, and versioned backend contract

**Files:** Backend files listed above, migration 003, `docs\api-m0.md`, initial `agent\internal\agent\protocol.go`, agent module locks, `compose.yaml` agent-tools profile, `scripts\test-agent.sh`, `scripts\build-agent.sh`, and `docs\testing\M1-LEDGER.md`.

**Interfaces:**

- Preserve `POST /api/agent/enroll` payload/response; persist input `simulated` and allow real devices without changing key authorization.
- `GET /api/agent/policy` returns `schema_version:1`, `policy_version`, `server_time`, `timezone`, `idle_seconds`, `collection_schedule`, `raw_retention_days`, `ingest_not_before`, `upload_seconds:60`, and `valid_for_seconds:86400` under device bearer authentication.
- `PUT /api/org/devices/{id}/employee` accepts `{employee_id:string}` (trimmed, at most 120 bytes); org-admin only, audit `device_employee_assigned`, own tenant only.
- Telemetry v2 extends the existing event with an optional `gap_reason` inside its typed gap payload; allow it only for v2 gap events and the spec's nine reasons. v1 canonical JSON/hashes must stay byte-compatible: omit the new field when empty. Keep an event schema version in server persistence so retries are interpreted consistently.
- Heartbeat without a version retains M0 semantics. Version 2 includes existing helper/extension values plus `schema_version:2`, `collection_state`, `policy_version`, `queue_events`, `queue_bytes`, `lost_events`, `loss_epoch`, and `last_error`. Accept only fixed collection/error enums, bounded identifiers, nonnegative counts, queue bytes at most 50 MiB, and safe integer counts. Persist latest operational values per device; never overwrite cumulative loss blindly without its epoch.
- Migration 003 adds device health JSON, health-receipt timestamp, and persisted event wire version with default 1; application DB schema becomes 3. Existing tables/data remain valid. No new employee-directory table.
- Agent `protocol.go` defines `Event`, `Payload`, `Policy`, `Heartbeat`, and `Acknowledgement` matching the published JSON contract exactly. `Event` carries stable ID/session/sequence/UTC observation and payload, never a device/organization selector.

- [ ] Write `TestNativeEnrollmentPolicyAndEmployeeIsolation`: real and simulated labels persist; owner/browser tokens cannot call policy; revoked device gets 401; employee assignment audits success and rejects owner/viewer/other tenant; invalid strings fail without writes.
- [ ] Write `TestTelemetryVersionCompatibilityAndCoverage`: replay stored v1 fixtures without hash changes; v2 reasons accepted only in gaps; unknown version/reason/health fields rejected; invalid batches remain atomic; health survives restart; readiness rejects schema 2 after migration target changes and accepts 3.
- [ ] Run `bash /home/husain/cherrysecurity-m0/scripts/test-backend.sh` in an approved isolated test context; record expected new-case failures, preserving M0 results.
- [ ] Implement routes, validation, parameterized writes, audit and migration. Derive policy version from canonical policy fields; include the existing irreversible ingestion watermark independently. Set health timestamps using server receipt time.
- [ ] Pin agent dependencies; add tools mounting `/home/husain/cherrysecurity-m0/agent` at `/agent`, with the existing non-root cache conventions. Build Go tests on Kali; cross-compile Windows binaries/test executables with `GOOS=windows GOARCH=amd64 CGO_ENABLED=0`. Do not install a global Go compiler on Windows. Native race instrumentation is tested on Linux core code; Windows test executables still run on Windows during approved acceptance.
- [ ] Run backend race/vet/module verification and compile agent protocol contract tests. Record module audit results and update the API contract/ledger; commit `feat: add native device policy and telemetry contracts`.

## Task 2 — Deterministic schedule and activity state machine

**Files:** `D:\Cherry-security\agent\internal\agent\policy.go`, `timeline.go`, and corresponding tests.

**Interfaces:** `ValidatePolicy(policy Policy) error`; `NewTimeline(policy Policy) *Timeline`; `(*Timeline).Observe(sample Sample) ([]Event,error)`; `(*Timeline).ApplyPolicy(policy Policy, at time.Time) ([]Event,error)`; `(*Timeline).Checkpoint() Checkpoint`; `RestoreTimeline(checkpoint Checkpoint, now time.Time) (*Timeline,error)`.

Define `Sample` with UTC time, monotonic elapsed duration, last-input age, application basename, session/lock/power state, and helper availability. `Checkpoint` contains serializable provisional intervals, current policy/epoch/sequence, finalized endpoint, and last durable observation; it contains no OS path or credentials. Service runtime supplies IDs and durable sequencing through one serialized timeline writer.

- [ ] Write table-driven `TestTimelineIdleScheduleAndRecovery`: input at 09:00:00, no later input, threshold 300 seconds → no active interval after 09:00:00 once 09:05:00 is observed; continuous input finalizes only the trailing threshold's predecessor; A→B focus change never overlaps; lock and suspend end attribution; overnight schedule validation rejects unsupported windows; unknown process produces a reasoned gap.
- [ ] Write `TestPolicyChangeDoesNotBroadenProvisionalCollection` and `TestClockAndSessionBoundaries`: intersect old provisional intervals with the policy effective when observed, split at the change boundary, handle DST/tick anomalies/UTC rollback, refuse unsupported sessions, and recover after a checkpoint with at most a five-second unflushed loss window. Short/ambiguous observations become unknown rather than invented activity.
- [ ] Run the focused agent core tests through the approved agent-tools service; expect missing types/functions or assertion failures before implementation.
- [ ] Implement the single disjoint state machine, maximum 60-second intervals, threshold-delayed finalization, schedule intersection, monotonic/UTC discontinuity detection at more than two seconds, and explicit epoch changes. Embed IANA tzdata. Cache policy for 24 hours; startup without trustworthy expiry requires refresh and collects no activity.
- [ ] Rerun all core tests with `-race`; verify exact seconds and invariants rather than only total row counts; commit `feat: classify scheduled Windows activity without overlapping intervals`.

## Task 3 — Durable bounded queue and verified delivery

**Files:** `D:\Cherry-security\agent\internal\agent\queue.go`, `client.go`, `logs.go`, corresponding tests; extend `protocol.go` only for these contracts.

**Interfaces:** `OpenQueue(path string, limitBytes int64) (*Queue,error)`; `(*Queue).CommitObservation(messageID string, checkpoint Checkpoint, events []Event) error`; `(*Queue).Batch(maxEvents,maxBytes int) ([]Event,error)`; `(*Queue).Acknowledge(submitted []Event, ids []string) error`; `(*Queue).Stats() QueueStats`; `(*Queue).Close() error`; `NewClient(baseURL string, caPEM []byte) (*Client,error)`; `(*Client).Policy(ctx context.Context, token string) (Policy,error)`; `(*Client).Upload(ctx context.Context,token string,events []Event) (Acknowledgement,error)`; `(*Client).Heartbeat(ctx context.Context,token string,health Heartbeat) error`.

Define `QueueStats` with event count, total file bytes, cumulative losses, loss epoch, and safe error code. Acknowledge an IPC message only after the transaction persists its checkpoint, immutable records, and message-deduplication marker together. Keep a bounded recent-message window tied to the active helper session; old sessions cannot replay into a new epoch.

- [ ] Write `TestQueueDurableAcknowledgementAndReplay`: crash between commit/pipe ACK/upload ACK/local delete, reopen and retry exact IDs/content, reject unknown/duplicate/missing ACK IDs without deleting records, and prove one helper message cannot create duplicate events after reconnect.
- [ ] Write `TestQueueFullAndJournalBudget`: force small limits, mix service/activity/provisional records, evict oldest pending records with a reserved loss ledger, retain newer observations, assert gaps do not overlap survivors, peak DB+journal bytes stay within budget, and storage refusal never returns a durable ACK. Sample transient journal size during transactions, not only afterward.
- [ ] Write `TestTransportTrustRevocationAndPoisonBatch`: local TLS servers with correct/wrong CA/SAN/expired certificate, redirects, timeout/500/retry, valid-server 401, malformed/oversized ACK, immutable 409 conflicts, retention expiry, and bounded split of invalid batches. TLS failures retain credentials; verified-server credential rejection stops collection and does not re-enroll.
- [ ] Run these tests RED, then implement single-writer SQLite DELETE journaling, 4 KiB pages, a 40 MiB maximum database, reserved metadata pages, constrained transaction mutations, bounded logs and actual-file monitoring. Reject unsupported limits rather than silently leaving SQLite pragmas unapplied. Set one database connection and bounded cache; keep total journal dirty-page budget below the 10 MiB reserve. If measurements disprove the cap, fix the transaction design before proceeding.
- [ ] Implement TLS 1.2 minimum, dedicated root pool, no redirects, response/body limits, one upload at a time, 500-event/768-KiB batch bound, 10-second timeout, and jittered retries. Preserve IDs on all uncertain outcomes. Discard permanently invalid/expired records with bounded loss metadata; 409 integrity errors pause the affected session's delivery. Encode logs before rotating so combined hard cap is respected.
- [ ] Run queue/client/core race tests, `go vet`, `go mod verify`, and vulnerability checks; measure an initial synthetic steady-state footprint to challenge the driver choice early; commit `feat: persist bounded telemetry and verify upload acknowledgements`.

## Task 4 — Windows authenticated IPC and service-owned secrets

**Files:** `D:\Cherry-security\agent\internal\agent\ipc_windows.go`, `credentials_windows.go`, their Windows tests, and protocol message declarations.

**Interfaces:** `ListenHelperPipe(ctx context.Context, binding SessionBinding, handler func(HelperMessage)(HelperReply,error)) error`; `ConnectHelperPipe(ctx context.Context,binding SessionBinding) (net.Conn,error)`; `ProtectCredential(token []byte) ([]byte,error)`; `UnprotectCredential(blob []byte) ([]byte,error)`; administrator setup channel `ServeEnrollment(ctx context.Context, enroll func(context.Context,[]byte) error) error`.

`SessionBinding` carries selected user SID, actual logon SID/session ID, and expected installed service identity. `HelperMessage` is protocol version 1 with a service session nonce, increasing sequence/message ID and typed observation/status request. Replies contain policy/status or durable ACK only, never credentials. Use go-winio only where its API preserves the required ACL/local-peer checks; use direct x/sys Windows calls where exclusive first-instance or peer-token validation requires them.

- [ ] Write `TestPipeIdentityBoundsAndReconnect` and `TestServiceIdentityDPAPI`: remote/other-user/other-session/squatted server, wrong service PID, stale nonce, oversized frame, stalled client, unknown field, retry after lost ACK, and inaccessible token files. A different user cannot decrypt/read credentials; helper status contains no token.
- [ ] Cross-compile test executables (compile-only now), then implement explicit pipe DACL rights, remote rejection, first-instance exclusivity, 64-KiB frames, 10-second IO timeouts, bounded concurrent connections, peer token/session checks and immediate impersonation revert. Enrollment uses the administrator-only pipe and service-side HTTPS/DPAPI storage before collection starts.
- [ ] Execute non-elevated isolated Windows pipe/DPAPI tests using temporary test-only identities/resources where permitted by Batch A; tests needing the actual service identity or second account remain explicitly pending Batch C. Never use the real device key in automated tests.
- [ ] Record which identity tests actually ran versus compiled-only; run core regression tests; commit `feat: secure Windows helper IPC and service credentials`.

## Task 5 — Windows collectors, visible status, and service runtime

**Files:** `D:\Cherry-security\agent\internal\agent\desktop_windows.go`, `services_windows.go`, `status_windows.go`, `runtime.go`, their tests, service/helper command entry points.

**Interfaces:** `RunService(ctx context.Context, config Config) error`; `RunHelper(ctx context.Context, binding SessionBinding) error`; `ObserveDesktop(ctx context.Context, emit func(Sample) error) error`; `ObserveServices(ctx context.Context, emit func(ServiceObservation) error) error`; `RunStatus(ctx context.Context, current func() Status) error`.

`Config` has validated endpoint/trust/config/data locations, selected user SID, and bounded operational settings; no arbitrary commands. `ServiceObservation` contains name/state/startup type/time only. `Status` contains fixed operational state, connection/helper/policy health, counts, and plain-language notice, not raw activity or credentials. Service runtime is the serialized owner of the queue and timeline; helpers never persist device tokens or upload directly.

- [ ] Write adapter-fixture `TestDesktopBoundariesAndNotice`, `TestInventoryReconcileAfterMissedChangeAndRecreate`, and `TestHelperDeathDoesNotFabricateActivity`: use injectable OS call boundaries only where needed; assert basename-only output, one-second coarse idle checks, inaccessible processes→unknown, no other-session attribution, five-minute inventory reconciliation, daily/reconnect refresh, no stale state after same-name recreation, and bounded notification handles.
- [ ] Run deterministic fixture tests RED and compile Windows adapters; implement WinEvent foreground notifications, WTS session/power notifications, last-input/session validation, and tray notice/status without a persistent window. No global keyboard/mouse hooks are needed to read contents. Stop application attribution when helper disappears; use service-observed session transitions and checkpoints for gaps.
- [ ] Implement SCM service inventory using query/read access and change notifications, with five-minute reconciliation and 24-hour refresh. Indicate partial inventory on access denial. No LocalSystem elevation or monitoring-driven service control.
- [ ] Wire SCM lifecycle and cancellation: clean bounded shutdown, graceful `SERVICE_STOPPED`, continue heartbeat where possible despite missing helper, policy refresh/expiry, queue loss/status, protected setup, and no collection before enrollment/valid policy.
- [ ] Run fixture/core tests and Windows compile checks; real foreground/tray/service-identity validation waits for the approved local test installation; commit `feat: collect Windows activity and expose employee status`.

## Task 6 — Explicit installation and administrator-managed lifecycle

**Files:** `D:\Cherry-security\agent\internal\agent\install_windows.go`, corresponding tests, control command, `scripts\build-agent.sh`, `docs\M1-WINDOWS-OPERATIONS.md`.

**Interfaces:** `PlanInstall(options InstallOptions) (InstallPlan,error)`; `ApplyInstall(ctx context.Context, plan InstallPlan) error`; `Uninstall(ctx context.Context, preserveData bool) error`. Plan includes resolved known folders, selected user SID, exact executable hashes, service/task names, ACLs and startup/recovery effects. Show the plan before elevation; refuse overwrite of an existing installation pending explicit upgrade approval. Uninstall requires elevation and preserves data by default; deletion needs a separate affirmative request.

- [ ] Write `TestInstallPlanRejectsReparseAndExistingResources`, `TestManagedServiceRecoveryAndAdminStop`, and `TestProtectedManagementAcl`: reject path escapes/reparse points and mismatched hashes, enforce standard-user query-only service access, protect task/binaries, and model recovery `[restart 10s,restart 30s,restart 60s,no action]` with one-day reset. Administrative stop must not create a recovery action or start another component that resurrects the service.
- [ ] Run pure planning/ACL construction tests RED; implement known-folder lookup, protected directory creation, quoted absolute service binary paths, LocalService/service SID, automatic delayed startup, bounded recovery, selected-user interactive limited task, and restrictive management ACLs. Use Windows APIs rather than building shell commands from untrusted arguments.
- [ ] Build three versioned Windows binaries and SHA-256 manifest into ignored artifacts. Document unsigned local-test restriction and customer-signing requirement. Do not install or request global software to make builds work; build through Kali tools and copy verified artifacts.
- [ ] Run install-planning tests and compile-only elevated lifecycle tests; record separate Batch C approval requirements and removal/resource-preservation commands. Commit `feat: package explicit managed agent installation`.

## Task 7 — Console coverage, policy visibility, and scoped HTTPS configuration

**Files:** Console files listed above; `D:\Cherry-security\deploy\agent-nginx.conf`, `scripts\prepare-agent-tls.py`, `compose.yaml`, `scripts\Sync-Kali.ps1`, `.gitignore`, `.dockerignore`, and relevant operations/API documentation.

**Interfaces:** `DeviceHealth` component consumes tenant-authorized device response health fields from Task 1. Administrator employee writes use the existing cookie/CSRF client. Agent-only ingress accepts exact enrollment/policy/heartbeat/events route+method pairs, rejects other paths, enforces body/time limits, and does not expose the dashboard.

- [ ] Write `TestDeviceHealthStatesAndAssignment` and Playwright `m1.spec.ts`: preserve simulator label, show real device/policy age/loss epoch/queue error/helper missing, explain threshold-plus-upload delay, prevent owner/viewer assignment, and handle expired sessions without secret persistence. Reuse Vitest/testing dependencies already present; add no dependency merely for rendering one health section.
- [ ] Run frontend tests RED; implement the health section, employee identifier form, collection notice/coverage wording, and accessible pending/error states. Keep owner provisioning separate from activity access. Update mobile assertions without collecting real activity screenshots containing sensitive names.
- [ ] Create private TLS-generation tooling that refuses existing secret paths, makes owner-only key files, validates SAN/expiry/key pairing, and emits only certificate metadata. Do not execute certificate generation against the live guest in Batch A. Add dedicated agent ingress binding through required explicit NAT-IP configuration; never default to `0.0.0.0`. Keep UI/API/DB bindings unchanged.
- [ ] Test certificate tooling and ingress in a dedicated temporary test project with synthetic keys/ports covered by Batch A, not the live NAT listener. Verify invalid CA/SAN/redirect fails, correct TLS succeeds, non-agent routes/methods fail, and no certificate/private key enters Git or Docker build contexts.
- [ ] Update Sync-Kali exclusions for agent binaries/test executables, fixture credentials, certificates and artifacts; verify an archive manifest excludes all private/generated paths before transfer. No deletion/synchronization of obsolete live files.
- [ ] Run frontend units/typecheck/build, browser tests against isolated fixtures, backend regression suite, and source secret/context checks; commit `feat: report native collection health and configure scoped agent HTTPS`.

## Task 8 — Controlled rollout, real-machine acceptance, and handoff

**Files:** `D:\Cherry-security\scripts\Invoke-AgentAcceptance.ps1`, `Measure-Agent.ps1`, existing backup/fresh/restore verification scripts as required by schema 3, `docs\testing\m1-results.md`, `M1-LEDGER.md`, all affected operations/status documents and `README.md`.

**Interfaces:** Acceptance script accepts an explicit test manifest listing only CherrySecurity resource names/paths/device identifiers and verifies that scope before mutation. Benchmark accepts process IDs verified against installed binary hashes and outputs bounded operational counters, never application titles or payloads. A declared eight-hour workload is a real elapsed measurement, not accelerated fake time.

- [ ] Implement and test script argument/scope validation with mocked process/resource providers before real use. Benchmark computes CPU as process CPU-time delta divided by elapsed time and logical processors; sample private bytes, peaks, bytes written, network counters, and queue/log file totals. Separate non-instrumented performance runs from race/debug builds.
- [ ] Present Batch B actions with actual NAT IP/source, collision checks, backup path, ingress secret paths, migration 003 and affected containers; obtain approval before applying. Preserve the existing owner and verify pre/post migration fingerprints of unchanged fields, readiness, M0 regression tests and a new isolated restore. Never use the old schema-2 fresh check unchanged; update expected schema to 3 and prove the new schema/health survives restore.
- [ ] Present Batch C install manifest and primary account choice; obtain approval/elevation. Install only the three named CherrySecurity resources/directories; enroll through the local hidden prompt. The human issues/enters the key locally and chooses the employee identifier. Verify protected service identity, helper permissions, scoped CA, and real-device enrollment.
- [ ] Obtain Batch D approval; run standard-user denial and administrator stop tests, bounded crash recovery, helper termination/missing coverage, known test-service state/reconciliation, app/idle/lock/suspend checks with two-second transition tolerance, malformed/queue-full/restart/clock tests using test-only storage and transport controls. Do not change the machine clock or unrelated services globally; use injectable clock for deterministic discontinuity tests and report that coverage limitation.
- [ ] Run the actual 30-minute network-outage acceptance using the scoped transport override while keeping Windows/Kali networking and other applications usable; reconnect and compare IDs/counts/totals. Then revoke only a disposable test device and confirm collection stops and no automatic re-enrollment occurs.
- [ ] Coordinate and run the real eight-hour reference workload after the human confirms availability. Publish CPU/RAM/disk/network samples and workload/hardware; mark pending or failed explicitly until actual elapsed evidence exists. Do not schedule unattended work without a user request, claim simulated timing as actual, or stop unrelated workloads to improve numbers.
- [ ] Run complete backend race/vet/mod verification, agent core race tests/Windows tests, frontend tests/build/browser acceptance, vulnerability checks, backup/restore and fresh install. Assess native/service security against the spec's OWASP and Windows controls; distinguish observed tests from compilation-only and review-only checks.
- [ ] Perform the final review required by the selected execution workflow, correct validated findings with targeted regressions, and record limitations and approved deviations. Update handoff documentation, commit `docs: record M1 Windows acceptance and operating procedures`, push only the approved branch, verify remote HEAD/clean source status, and report the actual completion state. Do not merge, delete branches, remove test resources or start M2 automatically.

## Reproduction command contract

Task 1 must make these commands work without a global Windows compiler installation. They write caches, test DB schemas and artifacts and therefore run only after Batch A approval:

```sh
bash /home/husain/cherrysecurity-m0/scripts/test-backend.sh
bash /home/husain/cherrysecurity-m0/scripts/test-agent.sh
bash /home/husain/cherrysecurity-m0/scripts/build-agent.sh
```

`test-agent.sh` runs module verification, core `go test -race -count=1 ./internal/agent`, and `go vet` under the Linux agent-tools profile; it also cross-compiles Windows test executables and all three commands. Test builds go to project artifacts, never protected Windows directories. Document any build-tag/platform exclusions explicitly. Windows-only tests run as test executables under the relevant approved identity; passing Linux tests or a Windows cross-build does not imply passing Windows runtime tests.

```powershell
npm.cmd --prefix D:\Cherry-security\web test
npm.cmd --prefix D:\Cherry-security\web run build
npm.cmd --prefix D:\Cherry-security\web exec -- playwright test --config=D:\Cherry-security\web\playwright.config.ts
```

These use only the isolated browser fixture profile until Batch B is approved. The source build and secret checks must exclude `*.exe`, `*.test`, credentials, fixtures, TLS private files and all artifacts from Git; public example configuration may contain placeholders only.

## Plan self-review and handoff

Coverage: design sections 1–3 map to Tasks 1, 5–6; section 4 to Task 4; section 5 to Task 1; section 6 to Tasks 2 and 5; section 7 to Task 3; section 8 to Task 7 and approval B; section 9 to the file map/approval batches; security and acceptance sections to all task negative tests and Task 8. Managed-service limits and administrator-stop behavior are explicitly preserved. The five Review Focus cases have named tests in their owning tasks.

Source-only tests cannot establish DPAPI under the actual service identity, second-user authorization, desktop/lock/suspend behavior, or eight-hour overhead. Those remain Batch C/D acceptance, not silently skipped requirements. Failure to obtain an approved identity/test window is a recorded gate, not completion.

Review this plan and approve Batch A to begin source implementation. Inline execution is recommended because the agent/backend/queue/policy contracts are tightly coupled and the user requested baby steps. Preserve B–D as separate approvals. If delegated implementation is preferred, the user must select it before agent dispatch.
