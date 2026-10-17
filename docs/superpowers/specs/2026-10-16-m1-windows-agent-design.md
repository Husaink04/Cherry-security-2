# CherrySecurity M1 Windows agent design

Date: 2026-10-16

Status: Proposed design for user review; implementation is not authorized by this document alone.

Baseline: PRD v0.3 and M0 commit `0ab36a5` on branch `m0`.

Approved work in this stage: create and commit this document, including the user's approved managed-service design revision. Implementation and installation remain outside this approval.

## 1. Intended outcome

Run CherrySecurity Agent as an administrator-managed background Windows service on the owner's existing Windows machine, with no persistent application window. Keep an employee status indicator and collection notice available, and report actual foreground application activity and Windows service observations to the Kali-hosted Console. Preserve organization isolation, single-use enrollment, reliable offline delivery, and low resource use. Work in small increments with recorded evidence rather than treating installation as acceptance.

The test endpoint reports Windows 11 Pro, version 10.0.26100, 64-bit. This establishes the initial reference OS only; it does not establish support for all Windows releases. Record CPU model, logical processors, physical memory, power configuration, and workload at benchmark time. Kali currently uses VMware NAT (VMnet8) at `192.168.193.129`; reverify addresses and SSH host identity before deployment.

M1 covers one administrator-selected primary local interactive Windows account per device. Reports initially remain device-based; an organization administrator can assign a plain employee identifier, without collecting a Windows username or integrating an employee directory. Concurrent RDP sessions and fast user switching are unsupported: close the supported session's interval and expose unavailable coverage rather than attributing another session's activity to that employee.

## 2. Approach and alternatives

Selected: a Go Windows service plus an unelevated Go session helper, an access-controlled local named pipe, and a service-owned SQLite queue. This follows the PRD and separates desktop observation from durable upload and service inventory.

A helper-only application is smaller but stops uploading when the user logs out and cannot independently report helper failure. A service-only application cannot reliably observe the interactive desktop because Windows isolates services in session 0. Neither delivers the M1 contract. Browser extensions remain M2; no browser transport is introduced now.

Build this as one native-agent subsystem with coordinated backend and reporting changes. Deliver it through checkpoints: transport/policy/enrollment; durable delivery; collectors/status; real-machine failure and performance acceptance. Each checkpoint must leave M0 behavior working.

## 3. Components and privilege boundaries

| Component | Responsibilities | Identity and limits |
| --- | --- | --- |
| CherrySecurityAgent service | Enrollment, policy retrieval, IPC validation, credential protection, queue, uploads, Windows service inventory | LocalService with a dedicated service SID and explicit resource ACLs; no LocalSystem fallback |
| CherrySecurity session helper | Foreground basename, last-input time, lock/session/power transitions, visible tray status | Selected interactive user, never elevated; no device token or direct backend access |
| Agent control utility | Local interactive setup, status, installation and explicit uninstall | Elevation only for protected installation/SCM/task/ACL operations; secrets entered through hidden prompts |
| Kali API and HTTPS ingress | Real enrollment, authenticated policy, ingestion and coverage, tenant-scoped reports | Existing runtime DB role; database and API ports remain private |

Start the helper through an explicitly installed logon task for the selected account, using that user's interactive token and limited run level. Do not have the low-privilege service acquire user tokens or create desktop processes. If the task cannot start, heartbeat reports helper missing. Existing user tasks and services remain untouched.

Configure the service for automatic delayed startup and bounded SCM crash recovery: restart after 10 seconds, 30 seconds, and 60 seconds for successive failures, then take no automatic action on further failures until the failure count resets after one failure-free day or an administrator intervenes. Include an explicit final no-action entry so SCM does not repeat the last restart action indefinitely. Do not reboot the machine or launch arbitrary recovery commands. An authorized administrator's explicit stop or uninstall must remain effective and must not be reversed by a helper, watchdog, task, or automatic reinstallation.

Set an explicit service DACL: ordinary users may query status but cannot stop, pause, reconfigure, delete, change permissions, or acquire ownership through service permissions. Restrict those management operations to administrators and SYSTEM; retain only the runtime rights needed by the service identity. Elevate the control utility for management actions. Restrict modification/deletion of the helper logon task to administrators and SYSTEM while permitting its configured user to execute it. Filesystem ACLs prevent ordinary users from replacing installed binaries or modifying service state. Do not change machine-wide user rights or weaken other services' ACLs.

These controls protect the service, not a process running under the employee's own identity. The employee may still terminate their session helper, sign out, disconnect the network, or power off the machine. The service continues operational heartbeat/upload where possible and reports helper missing; it must not fabricate application activity or silently run a privileged desktop collector. Local administrators and SYSTEM can disable or uninstall the product. No kernel driver, process hiding, Task Manager evasion, or anti-uninstall mechanism is introduced.

The helper uses foreground-change notifications and session/power notifications, plus a one-second lightweight state check for idle detection and recovery. Obtain the executable path with only the query rights required, reduce it immediately to a basename, and never persist or transmit the path. Protected/inaccessible processes become an unknown interval. No process command lines, window titles, documents, input contents, screenshots, clipboard, audio, or video are collected.

The service enumerates service names, state, and startup type using read/query permissions, subscribes to supported change notifications, and reconciles every five minutes. Deduplicate unchanged observations; emit a new inventory snapshot periodically so server retention does not erase an otherwise unchanged service indefinitely. Refresh at least daily and after reconnect. Do not collect binary paths or account credentials. A denied query is unknown coverage, not permission to elevate. Never stop or reconfigure unrelated services to test monitoring.

## 4. Local IPC and credential protection

Use versioned, length-prefixed JSON messages on a local-only named pipe. Maximum message size is 64 KiB, with fixed message types, bounded fields, read/write timeouts, and bounded connections. Reject remote clients. Create the first pipe instance exclusively to detect name squatting.

Use an explicit DACL granting only SYSTEM, administrators, the service SID, and the selected user's SID the necessary pipe rights. LocalService cannot reliably discover a new interactive logon SID before the helper first connects after sign-in. On every connection, authenticate the client token's selected user SID, active session ID, and logon SID by impersonation for inspection only, immediately reverting; never execute work as the client. The helper verifies the server process against the installed SCM service PID, service identity, and protected executable location before exchanging observations. Test wrong-user, wrong-session, oversized, malformed, and impersonated-server cases.

IPC has no shell commands, arbitrary paths, service-control instructions, or arbitrary SQL. Bind each connection to a service-issued session nonce; accept monotonically increasing helper message numbers and reject stale/repeated messages. Acknowledge observations only after a durable local transaction. The helper retries unacknowledged messages using the same identifiers. The service chooses device identity, event IDs, and upload credentials; helper-supplied identity cannot change tenant or device.

Store the device token in a DPAPI blob protected under the service identity, with UI disabled. Enrollment must execute inside the service so the token is never initially protected under the installing administrator's profile. The administrator conveys the enrollment key through a separately restricted setup channel accessible only to administrators and the service, with the same peer checks and bounds. Do not use a command-line secret or environment variable. Provision a protected temporary key file only if an interactive pipe is unavailable, under an explicitly approved alternative design; it is not the default.

Use restrictive Windows ACLs on credentials, queue, logs, and config. The helper cannot read the queue or token. Do not rely on machine-wide DPAPI alone: its machine scope is not an authorization boundary. Administrators/SYSTEM and malware controlling the selected user remain outside the anti-tampering guarantee; this is monitoring software, not an anti-cheat or endpoint protection product.

## 5. Enrollment, employee mapping, and API compatibility

Keep the existing key lifecycle and transaction: organization derives exclusively from the key, one redemption creates one device, token hashes stay server-side, and token revelation happens once. Real enrollment sets `simulated:false`; the backend must persist that value rather than the current hardcoded `true`. M0 simulated enrollment remains supported and visibly labeled.

Before sending a key, the service verifies the configured HTTPS endpoint and scoped trust root. Persist returned credentials durably before collection starts. If enrollment committed but its response was lost, show a specific recovery state; do not silently mint another identity or retry a used key indefinitely. An administrator must identify/revoke any orphan endpoint and obtain a replacement key. Automatic lost-response credential recovery is outside this milestone, and the limitation is visible in setup documentation.

Add device-authenticated `GET /api/agent/policy`. Return policy version, server UTC time, organization IANA timezone, schedule, idle threshold, retention acceptance floor, upload interval, and policy validity duration. It must return no other organization's data, enrollment keys, or browser-session credentials. Use a deterministic version of the collection-policy fields; record the version applied by the agent in heartbeat health.

Add admin-only `PUT /api/org/devices/{id}/employee` with a trimmed identifier of at most 120 bytes and an empty value to unassign. Use the existing `devices.employee_id`; validate and audit changes, enforce tenant scoping, and keep the value out of device policy. It is an administrator-supplied label, not evidence that the physical user has been authenticated as an employee.

Preserve telemetry schema version 1 for M0 clients. Add version 2 for native agents, with explicitly typed coverage reasons and richer heartbeat health. Both versions retain a 1 MiB request limit, 500-event maximum, stable IDs, transactional acknowledgement, current timestamp bounds, and non-overlapping foreground categories. Reject unsupported fields/versions rather than ignoring them. Database schema versions and telemetry versions are separate.

Version 2 adds gap reasons `helper_missing`, `suspended`, `logged_out`, `unsupported_session`, `clock_discontinuity`, `queue_overflow`, `local_storage_failure`, `process_unavailable`, and `policy_expired`. A gap represents missing observation, never active or idle time. Outside schedule, expose a collection-status state without recording activity intervals. Browser health remains missing/not installed during M1.

Heartbeat reports collection state, helper health, policy version, pending event count/bytes, and cumulative lost-event count with a counter epoch. These are bounded operational fields, not activity payloads. Persist the latest values and surface them in the device view. A loss counter must remain visible even if its detailed gap event was evicted or has aged beyond ingestion retention. The server cannot attest that an endpoint's observations are truthful.

## 6. Collection timeline and policy behavior

Use a single interval state machine for application, idle, locked, and gap categories. Durations are nonnegative and disjoint. Split at policy boundaries, local midnight, state changes, and a maximum 60-second interval. Server timezone aggregation remains authoritative. Record server receipt separately from observation time.

Idle classification needs delayed finalization. Keep the trailing configured idle-threshold window provisional, with a durable checkpoint at least every five seconds. When the threshold is reached, classify from the last observed input as idle; never upload that period first as active and later overwrite it. With continuous input, finalize data older than the threshold. On a known lock/logout/schedule boundary, finalize the provisional window using the state observed up to that boundary. Explain the resulting dashboard delay (normally the idle threshold plus upload delay) in the UI and runbook.

Use monotonic elapsed time within a running session and correlate it with UTC anchors. Handle tick wrap and non-incremental last-input timestamps conservatively. A material wall-clock discontinuity (more than two seconds from the monotonic prediction), suspend, lost helper, or ambiguous session transition closes active attribution. Never fabricate foreground duration across an unobserved period. New resume/clock epochs receive new session IDs; if the wall clock moves backward, wait until UTC reaches the last finalized endpoint before starting a new interval to avoid device-wide overlap. Expose clock-error status meanwhile.

Lock ends application observation; only lock duration is recorded during scheduled hours. Logout/suspend/helper loss become gaps when the missing interval can be bounded. Restart uses the last durable checkpoint; at most five seconds of unflushed observation may be lost, and the interval after the checkpoint is unknown until the current state is established. If a historical gap is beyond server retention, use operational loss/coverage status instead of inventing a current-day interval.

Retrieve policy at startup and every 60 seconds. Persist a validated cache with a 24-hour validity measured against a monotonic runtime deadline and persisted UTC expiry. If local time becomes unreliable on restart, require a fresh server policy. No initial valid policy means no activity collection. Expired cached policy stops activity collection and reports policy unavailable; reconnection resumes after validation. During an outage the last known policy remains effective until expiry, so server policy changes are not immediate. Show policy age to administrators.

Schedules use the existing organization IANA timezone, Sunday=0, and same-day windows; unrestricted collection must be explicit. Handle daylight-saving transitions using timezone data, not a fixed UTC offset. Intersect every collected interval with allowed windows, including retrospectively finalized idle intervals. Service inventory is operational metadata and may continue outside activity hours; disclose this in the employee notice. Heartbeats and retries continue while activity collection is stopped.

The helper runs without a persistent application window. Its employee tray indicator remains available and shows collecting, idle, locked/paused, outside schedule, offline, helper/service error, policy unavailable, or revoked. Opening status/notice explains the collected fields: application basenames and service metadata, with browser-domain collection not yet installed. It never exposes credentials. Windows may place tray icons in its overflow area; the installer and notice must explain where status can be found. The employee-facing interface has no stop/uninstall controls; administrator management is separate. Missing tray/helper means desktop activity collection is unavailable, not covert fallback collection.

## 7. Durable queue, delivery, and bounded resources

SQLite is service-owned and single-writer, with a pinned maintained Go driver selected and checked during implementation planning. Persist provisional checkpoints, immutable finalized events, upload state, session sequences, policy, and loss counters transactionally. Keep device secrets outside event rows. Bound memory buffers and database caches; no unbounded goroutines, channels, or retry lists.

Use rollback-journal DELETE mode initially for simpler total-disk accounting. Limit the database to 40 MiB via page size/page count; reserve the remaining 10 MiB for a bounded transaction journal and overhead. Cap each transaction's dirty pages/bytes and measure database plus journal at peak: `max_page_count` alone is not proof of the 50 MiB total cap. Reuse free pages rather than repeatedly vacuuming. Abort and expose storage failure if actual limits cannot be maintained; acceptance requires forced-full measurements.

When admission would exceed the queue budget, transactionally discard the oldest unacknowledged finalized records, retain/update a reserved loss ledger, and admit newer records. Replace discarded foreground ranges with coalesced gap information without overlapping surviving intervals. Reserve space for checkpoint and loss metadata so a full queue cannot erase the evidence of loss. Count lost service observations separately. If even the reserve cannot be written, stop collection and show an error; do not claim a durable event acknowledgement.

Default upload/heartbeat cadence is 60 seconds; upload interval is constrained to 60–300 seconds. Use at most 500 events and a conservative serialized byte budget below the server's 1 MiB limit. Do not add compression until receiver support and measurements justify it. Request timeout is 10 seconds; jittered exponential retry starts at two seconds and caps at five minutes. Only one upload is in flight.

Delete queued events only after validating durable acknowledgement IDs against the submitted batch. Network errors retain the exact immutable batch identities. For permanent validation errors, isolate the failing record through bounded batch subdivision, count its loss, and preserve metadata in the loss ledger instead of retrying a poison batch forever. Never log rejected payloads. Conflicting IDs/overlaps trigger a visible integrity error and pause that session's activity delivery pending diagnosis; do not mutate or regenerate already-sent event contents. Expired events are explicitly discarded with counters, respecting the returned ingestion watermark.

An authenticated 401 from policy/heartbeat/upload stops collection and upload, marks credential invalid/revoked, and retains bounded local state for an approved recovery decision. Do not automatically re-enroll. A 401 during initial enrollment is a separate key failure. Server errors are retried without treating them as revocation.

Runtime targets from the PRD remain provisional: combined service/helper private bytes at most 50 MiB; average CPU below 1% of total machine capacity over eight hours; queue including journal at most 50 MiB; logs at most 10 MiB. Bound the two processes' logs together, for example two files of at most 2.5 MiB each per process, checking encoded record length before writes. Logs contain error categories and counts only, never executable names, service inventories, credentials, or activity payloads. Report peaks, disk writes, outbound bytes, and build footprint separately. The chosen SQLite driver must meet these measured targets or be reconsidered before completion.

## 8. HTTPS and local topology

Recommended pilot transport: direct HTTPS from Windows to a dedicated agent-only ingress on Kali's NAT interface, proposed `https://192.168.193.129:8443`. The ingress proxies only the agent routes, uses a private development CA with an IP SAN, and leaves the existing dashboard on loopback SSH forwarding. Certificate validation and endpoint hostname/IP checks remain enabled; minimum TLS 1.2. Do not expose PostgreSQL, API container ports, or the Console through this listener.

Keep the CA private key and server key only in guest secrets storage. Provision only the CA certificate to the agent through host-verified SSH. Scope that CA to the agent's HTTP client; do not install a machine-wide trusted root or change browser trust. Certificate renewal and VM-IP changes require documented regeneration/reconfiguration, not disabled validation. Reject redirects so bearer tokens cannot leave the configured origin.

This listener, its certificate generation, Compose changes, and any source-restricted guest firewall rule require a later concrete approval identifying the interface/source/paths. Recheck actual host NAT-interface address and existing listeners first. No Windows inbound firewall opening or router forwarding should be necessary. If direct NAT routing cannot be established safely, propose a verified SSH tunnel carrying HTTPS as an explicit alternative; do not fall back to HTTP.

## 9. Planned files and resources

These are intended implementation boundaries, not authorization to modify them now. Paths are explicit for the current workspace; portable application code/config must not embed this developer machine's paths.

| Paths/resources | Intended change |
| --- | --- |
| `D:\Cherry-security\agent\` | New Go module, service/helper/control entry points, timeline/policy/queue/transport/Windows adapters, unit and integration tests |
| `D:\Cherry-security\backend\internal\app\provisioning.go`, `app.go`, `telemetry.go`, `reports.go`, `database.go` | Real enrollment, device policy, versioned events/health, employee label, schema readiness |
| `D:\Cherry-security\backend\internal\app\migrations\003_native_agent.sql` and backend test files | Additive health/policy/coverage persistence and negative/regression tests; preserve M0 records |
| `D:\Cherry-security\web\src\organization.tsx`, `model.ts`, `style.css`, relevant frontend tests | Real-device coverage/policy/loss display, employee identifier, latency notice |
| `D:\Cherry-security\compose.yaml`, `scripts\`, new agent ingress configuration | Scoped HTTPS and reproducible build/install/test tooling; maintain private DB |
| `D:\Cherry-security\docs\` and `README.md` | Implementation plan, Windows operations, privacy notice, protocol contract, acceptance evidence |
| `/home/husain/cherrysecurity-m0` | Approved source synchronization, image build/deployment, additive migration, scoped ingress and secret files after implementation approval |
| `C:\Program Files\CherrySecurity` | Protected versioned service/helper/control binaries and non-secret installation manifest |
| `C:\ProgramData\CherrySecurity` | ACL-protected service config, DPAPI credential blob, SQLite queue, bounded logs, scoped public CA certificate |
| Windows SCM service `CherrySecurityAgent`, task `CherrySecurity Session Helper` | Automatic delayed service startup, bounded crash recovery, administrator-only management ACLs, selected user's limited logon task; scoped install/start/stop/uninstall actions |

Resolve Program Files/ProgramData through Windows known-folder APIs rather than assuming C: in portable installers. Before modifying an existing installation, refuse path/reparse-point escapes, inspect ownership and existing state, and obtain approval for the concrete upgrade/replacement. No auto-update is introduced. Development binaries are unsigned and restricted to this owner's controlled test; signed installers and verified upgrade packages remain required before customer deployment. Uninstall stops only CherrySecurity resources and preserves queued data/credentials unless deletion is separately approved.

## 10. Security requirements and verification

Official OWASP baseline checked on 2026-10-16: Top 10:2025. This is risk guidance, not certification. Apply its categories alongside Windows-specific controls:

| Risk category | M1 requirement and evidence |
| --- | --- |
| Broken access control | Tenant-scoped employee writes/device policy, revoked-token rejection, selected-user/session pipe ACL and impersonation tests |
| Security misconfiguration | Restricted agent-only ingress, fail-closed policy/TLS, non-admin helper, protected filesystem paths |
| Software supply chain failures | Pin Go modules/SQLite driver, verify sums, vulnerability checks and build checksums; no customer release of unsigned binaries |
| Cryptographic failures | Verified TLS/scoped CA, OS-generated randomness, DPAPI and restrictive ACLs; no secret arguments/logs |
| Injection | Strict typed JSON, parameterized SQL, bounded strings, basename-only data, no command execution from IPC |
| Insecure design | Visible collection, offline policy expiry, disjoint state machine, explicit unsupported sessions and loss states |
| Authentication failures | Single-use enrollment, service-owned credential storage, authenticated local peers, no shared installer secret |
| Software/data integrity failures | Immutable event identities, durable acknowledgements, replay tests, protected binaries and config |
| Security logging/alerting failures | Audited employee assignment and enrollment/revocation; visible pipe/storage/policy/integrity errors without payload logs |
| Mishandling exceptional conditions | Disk full, queue full, partial writes, malformed ACKs, clock changes, suspend, inaccessible processes, service/helper crashes, network failures |

## 11. Acceptance and human intervention

1. Preserve all M0 tests and simulator behavior; migrate existing data additively and verify backup/restore with the new schema.
2. Enroll the actual endpoint with a Product Owner-allocated key over verified HTTPS. Show a real-device label, correct organization, and configured employee identifier. Reject reused/revoked keys, wrong CA/hostname, unexpected redirects, and unauthorized policy/employee operations.
3. Drive the collector state machine with a fake clock and Windows-adapter fixtures: app changes, retroactive idle, schedule edges, timezone/DST transitions, lock/unlock, logout, suspend/resume, helper disconnect, tick anomalies, and wall-clock jumps. Assert exact disjoint intervals and no false active attribution.
4. On the actual endpoint, perform a controlled app-switch/idle/lock/suspend scenario and compare reported intervals with a declared tolerance of two seconds for observable transitions. Suspend and lock require the human to resume/unlock the computer. Record protected-process limitations explicitly.
5. Install a dedicated harmless CherrySecurity test service only with approval, change that service's state, and verify observation plus five-minute reconciliation after suppressing one notification. Preserve all unrelated services.
6. Simulate a 30-minute upload outage using an agent test transport override, without changing the machine's global network settings. Reconnect and compare IDs/counts/totals: no duplicate activity, no lost acknowledged records, and correct policy/coverage state.
7. Force a small queue in tests; crash/restart both processes, corrupt test-only acknowledgements, expire policy, revoke test credentials, and deny storage. Demonstrate the disk cap including journal, reserved loss evidence, controlled stop, and authenticated IPC rejection.
8. Run an eight-hour reference workload on this Windows machine. Measure combined private bytes, CPU normalized by logical processors, peaks, outbound bytes, and total disk writes at documented sampling intervals. Short smoke checks cannot satisfy the eight-hour gate. A target deviation is reported and investigated, never silently relabeled passing.
9. Provide reproducible installation/uninstallation commands, scoped ACLs, collected-field notice, TLS renewal steps, queue/recovery procedures, and actual evidence. No customer deployment is authorized by M1 completion.
10. As a standard user, verify service stop/pause/reconfiguration/uninstall and binary/task modification are denied, while employee status and the collection notice remain accessible without a persistent window. Verify automatic startup and bounded crash recovery using only the dedicated CherrySecurity service. Verify an administrator can stop/uninstall it without automatic resurrection. Terminate the user's helper in a controlled test and confirm missing coverage, continued service connectivity where possible, and no false activity. Record that administrator access, network loss, logout, and shutdown remain outside prevention guarantees.

Human actions required later: approve the concrete implementation/deployment batch; approve Windows elevation for the dedicated service/task/directories; supply an enrollment key through the local hidden prompt; choose the primary Windows account and employee identifier; perform lock/unlock and suspend/resume; and keep the endpoint available for the declared eight-hour workload. Further firewall, certificate, service, or file deletion actions require approval covering their exact scope. Do not ask for passwords or private keys in chat.

## 12. Sources and design status

Primary guidance checked during design:

- [OWASP Top 10:2025](https://top10.owasp.org/2025/).
- [Microsoft service isolation, privileges, notifications, and session 0](https://learn.microsoft.com/en-us/windows/win32/services/service-changes-for-windows-vista).
- [Microsoft service security and access rights](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights).
- [Microsoft service failure actions](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/ns-winsvc-service_failure_actionsw).
- [Microsoft LocalService identity](https://learn.microsoft.com/en-us/windows/win32/services/localservice-account).
- [Microsoft named-pipe security and access rights](https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipe-security-and-access-rights).
- [Microsoft DPAPI CryptProtectData](https://learn.microsoft.com/en-us/windows/win32/api/dpapi/nf-dpapi-cryptprotectdata).
- [Microsoft session-local last-input behavior](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-getlastinputinfo).
- [Microsoft session notifications](https://learn.microsoft.com/en-us/windows/win32/api/wtsapi32/nf-wtsapi32-wtsregistersessionnotification).
- [SQLite pragmas and page/journal limits](https://www.sqlite.org/pragma.html).

This document has been checked for consistency with existing M0 routes, schema, retention watermark, and PRD limits. It defines proposed behavior, not tested native-agent capabilities. Next gate: user reviews this written spec. Once approved, create a detailed implementation plan with exact task boundaries and write effects for approval; no agent code, installation, certificate, network, or database changes are included in this design-only commit.
