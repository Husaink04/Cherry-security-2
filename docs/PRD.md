# CherrySecurity — Product Requirements Document

Status: Draft for review before implementation  
Version: 0.3  
Date: 2026-10-16  
Product and brand name: CherrySecurity  
Working repository: Cherry-security

## 1. Product intent

Build CherrySecurity, a commercial employee monitoring product for company-managed computers. It should show application usage, browser domain usage, Windows service status, and device connectivity while keeping endpoint CPU, memory, disk, and network usage low.

Use the exact brand spelling **CherrySecurity** in product-facing text, documentation, dashboard branding, installer names, and employee collection notices. Use **CherrySecurity Agent** for the Windows endpoint software and **CherrySecurity Console** for the web interface. The descriptive product category is **employee activity and endpoint monitoring**; the name does not imply antivirus, threat detection, or endpoint protection capabilities.

The brand is selected for development. A preliminary web check found existing uses of similar wording, including [Cherry Security Company](https://www.cherrysecurity.com/), the [Cherry Security cybersecurity blog](https://cherry-security.com/), and [CHERRY Security products](https://www.cherry.de/en-gb/industrial/security). Domain availability and trademark clearance have not been established; resolve brand availability before a public commercial launch.

Develop in small, independently testable milestones. The Kali Linux VM hosts the complete local server stack: Go backend, PostgreSQL database, and React dashboard hosting. The existing Windows machine runs the endpoint agent and is used for real collection tests.

The customer employee count is unknown. Support multiple customer organizations in the data model and authorization design, but establish capacity through measurements rather than promising unlimited scale.

## 2. Confirmed decisions and assumptions

### Confirmed

- The product and brand name is CherrySecurity.
- Go for the backend and endpoint agent.
- React for the administrator frontend.
- Browser, application, and Windows background service monitoring.
- Low endpoint resource consumption is a primary requirement.
- The Kali VM hosts the complete backend, database, and dashboard server stack for local testing.
- An existing Windows machine is available for endpoint-agent installation and testing.
- The Product Owner creates organizations and allocates endpoint enrollment keys to each organization.
- The intended outcome is a commercial product.
- Implementation follows PRD review and proceeds in baby steps.

### Working assumptions to validate

- Windows is the first supported endpoint OS. The exact supported Windows releases will be selected before the Windows pilot.
- Chrome and Edge are the first supported browsers; managed extension installation will be validated during the browser milestone.
- Initial monitoring is observation and reporting, without remote control or policy enforcement.
- One primary interactive user per device is sufficient for the pilot. Concurrent RDP sessions and fast user switching require explicit testing before support is advertised.
- Employee records may initially use administrator-assigned identifiers. HR integrations are deferred.

Kali is the server environment; the existing Windows machine is the monitored endpoint. A Linux monitoring agent is outside the initial scope.

## 3. Users and core jobs

| User | Core job |
| --- | --- |
| Product Owner | Create organizations, provision their initial administrators, and issue, allocate, and revoke organization-bound endpoint enrollment keys |
| Organization administrator | Use allocated keys to enroll devices, configure collection, manage organization access, and inspect organization activity |
| Organization viewer | Read reports for their organization without changing configuration |
| Employee | Understand collection status and what is collected on their managed device |
| Product operator | Deploy and maintain the platform without automatically gaining access to customer activity |

The Product Owner has platform provisioning authority; this does not automatically grant access to employee activity. Product-operator support access is outside the pilot. It must be explicitly designed and audited before commercial use.

## 4. Initial product scope

### Organization provisioning and enrollment-key allocation

- Only the Product Owner can create organizations and provision their initial organization administrators. Customer self-service organization creation is outside the initial scope.
- The Product Owner generates and allocates a requested number of endpoint enrollment keys to a specific organization.
- For the initial version, one key enrolls one endpoint. Enrollment keys are expiring, single-use secrets; they are distinct from the device credentials used after enrollment.
- Organization administrators can view key allocation/status and use allocated keys for installation, but cannot mint keys or allocate them to another organization.
- Show key metadata and lifecycle state: allocated organization, creation time, expiry, unused/used/expired/revoked state, and enrolled device where applicable.
- Reveal each key secret once at issuance for controlled handoff to the organization administrator; store only a verification hash and never include the secret in logs or audit records. Issue a replacement if the secret is lost.
- Consume keys atomically during enrollment so simultaneous requests cannot enroll multiple endpoints with one key.
- The Product Owner can revoke unused keys and issue replacements. Revoking a used key does not revoke its device credentials; device revocation is a separate action.
- Audit organization creation, initial administrator provisioning, key issuance/allocation, redemption, and revocation.

### Device enrollment and connectivity

- Enroll a device into the organization bound to its Product Owner-allocated enrollment key. An endpoint cannot select or override that organization.
- Issue unique, revocable device credentials; do not embed shared secrets in installers.
- Show device identifier, assigned employee, hostname, OS, agent version, last contact, and collection status.
- Send a heartbeat every 60 seconds by default. Mark connectivity stale after three missed intervals and offline after five minutes without contact.
- Display connectivity separately from collection health. An online service does not prove that the helper or browser extension works.
- Allow administrators to revoke a device and prevent further accepted uploads from it.

### Application activity

- Record the foreground application identity and active duration.
- Separate foreground activity from idle, locked, logged-out, suspended, and unobserved periods.
- Default idle threshold: five minutes, configurable by organization.
- Reclassify the period after the last input as idle when the threshold is reached; do not count it twice as application activity.
- Do not collect document names, command lines, or window titles by default.
- Clearly label foreground duration as activity, not a measure of employee productivity.

### Browser activity

- Use an extension to observe active tabs and navigation in supported browsers.
- Store normalized hostnames, such as `docs.example.com`, and durations by default.
- Remove URL paths, query strings, fragments, credentials, and page titles before local persistence or upload.
- Count website activity only when the relevant browser window is foregrounded and the user is active.
- Do not count every open tab as active usage.
- Browser usage is a breakdown of application usage; reports must not add both together as separate work time.
- Show extension missing, disconnected, unsupported browser, and policy-excluded activity as coverage states.
- Exclude private/incognito browsing from initial support and document that coverage limitation.

### Windows services and background processes

- Capture Windows service inventory, startup type, current state, and observed state changes.
- Periodically reconcile inventory to recover from missed changes.
- Track service identity separately from process identity because a process may host multiple services.
- Keep foreground application activity separate from background execution.
- Detailed all-process CPU, memory, disk, and network attribution is deferred. It is not required to deliver service monitoring.

### Administrator dashboard

- Product Owner view for organization creation, initial administrator provisioning, and endpoint enrollment-key allocation/status.
- Organization login and role-based access.
- Device list with connectivity and collector-health indicators.
- Device detail with activity timeline and service inventory.
- Daily application and browser-domain summaries, filterable by employee, device, and date.
- Organization settings for idle threshold, collection schedule, and retention.
- Show report timezone, last update, missing coverage, and simulated-data labels.
- Refresh reports on a modest interval; real-time streaming is not required initially.

### Transparency and collection boundaries

- Provide a visible employee status indicator showing collection state and a plain-language description of collected data.
- Allow administrators to define a collection schedule and timezone. Activity outside that schedule is not collected; an unrestricted schedule must be an explicit setting.
- Stop activity collection on session lock or logout; resume only after a valid active session is observed.
- Keep browser page content, keystrokes, clipboard contents, passwords, screenshots, audio, and video outside the initial product scope.
- Review customer notice and deployment requirements for intended sales regions before commercial launch.

## 5. Architecture and technology

```text
Existing Windows test machine
  Browser extension (TypeScript)
       -> user-session helper (Go)
       -> Windows service (Go, local bounded queue)
                         |
                         | HTTPS batched events + heartbeat
                         v
Kali VM — complete local server stack
  Go API -> PostgreSQL
     ^
     | authenticated API
  React + TypeScript dashboard
```

| Layer | Choice | Responsibility |
| --- | --- | --- |
| Endpoint service | Go with Windows APIs | Service inventory, queue, heartbeat, uploads, configuration |
| Session helper | Go with Windows APIs | Foreground application and session/idle state |
| Browser extension | TypeScript, Manifest V3 | Supported-browser active hostname events |
| Endpoint queue | SQLite | Durable pending events with bounded storage |
| Backend | Go standard HTTP library | Organization provisioning, key allocation, authentication, enrollment, ingestion, reports, configuration |
| Frontend | React, TypeScript, Vite | CherrySecurity Console for Product Owner and organization administrators/viewers |
| Database | PostgreSQL with SQL migrations | Organization-scoped records and summaries |
| Local deployment | Docker Compose | API, web frontend, and database lifecycle |
| Windows packaging | Signed MSI before customer pilots | Installation, uninstall, and managed rollout |

Use a modular monolith for the backend. Separate enrollment, ingestion, reporting, and authorization in code without independently deploying them. Do not introduce Kubernetes, Redis, Kafka, or microservices until measured requirements justify them.

Windows services and user desktop sessions require separate execution contexts. Use authenticated, access-controlled local IPC between the service and helper. Validate the browser-to-helper transport during its milestone; do not expose an unauthenticated local HTTP collector.

Kali is the development environment. Production hosting and its operating system will be selected separately after the pilot.

## 6. Data and ingestion requirements

Core records: platform Product Owner account, organization, administrator membership, employee, device, enrollment key (verification hash, organization, issuer, lifecycle timestamps, redemption/device reference), device credential, collection policy, activity interval, service observation, heartbeat, daily summary, and audit event.

- Every customer record belongs to an organization.
- Derive organization and device identity from authenticated credentials. Never trust identifiers supplied in an event payload as authorization.
- Give events stable identifiers. Retried batches must not create duplicate activity or inflate durations.
- Include schema version, session identifier, observed timestamps, and sequence information sufficient to detect gaps.
- Record server receipt time separately from device event time. Flag implausible clocks and events rather than silently assigning them to the current day.
- Store timestamps in UTC and aggregate reporting days using the organization's configured timezone.
- Use monotonic elapsed time within sessions where possible; handle suspend/resume and reconnect explicitly.
- Acknowledge ingestion only after durable database acceptance. Remove queued records only after acknowledgement.
- Bound request sizes, record counts, string lengths, and accepted time ranges. Return actionable errors for malformed data.
- Support out-of-order offline uploads without double counting or silently overwriting newer service observations.

Initial retention defaults: seven days for raw activity/service observations and 30 days for daily summaries. Heartbeats update current device state rather than creating an indefinite raw heartbeat history. Make retention explicit in organization settings; automated cleanup must delete expired records and derived data must obey its own retention limit.

## 7. Endpoint performance and reliability

The following are provisional acceptance targets, not measured guarantees. Validate them on a documented low-spec Windows reference machine before changing them into marketing claims.

| Metric | Pilot target |
| --- | --- |
| Service + helper memory | Combined private bytes at or below 50 MiB at steady state; browser overhead reported separately |
| Service + helper CPU | Average below 1% of total machine CPU over a representative eight-hour workload; record peaks separately |
| Offline event queue | 50 MiB maximum including SQLite journal/WAL overhead |
| Diagnostic logs | 10 MiB total cap with rotation and no activity payloads or secrets |
| Event uploads | Default every 60 seconds, configurable within one to five minutes |
| Recovery | Resume normal collection/upload after process restart or network restoration without duplicate records |

- Prefer OS change notifications and coarse reconciliation over frequent full scans.
- Persist batches rather than writing for every focus change. Document a maximum five-second unflushed activity loss window for an unexpected process crash.
- Bound in-memory buffers and upload batch size, compress meaningful batches, and use jittered exponential retry backoff.
- Do not compact the local database continuously. Verify that queue cleanup releases or reuses bounded disk space.
- When the queue fills, discard the oldest unacknowledged activity to admit newer data, count the loss, and report a visible coverage gap. Never allow unlimited disk growth.
- Measure outbound bytes, disk bytes written, browser-extension overhead, and battery impact during the pilot; establish budgets from those results.
- Distinguish installer footprint from runtime data limits.
- Initial service inventory reconciliation may run every five minutes; configurable allowlists can restrict status subscriptions to relevant services.

## 8. Security and commercial foundations

- Enforce organization isolation on every read/write path and verify it with two test organizations.
- Support a platform Product Owner role and organization-scoped administrator/viewer roles with server-side authorization. Organization users cannot access platform provisioning endpoints or other organizations' key metadata.
- For the local pilot, bootstrap the Product Owner account securely; the Product Owner provisions organizations and their initial administrator accounts. Use securely hashed passwords and revocable sessions. Self-service signup, SSO, and account recovery are later work.
- Use HTTPS whenever endpoint data crosses the VM boundary. Bind local-only development services to loopback by default.
- Keep PostgreSQL off publicly reachable interfaces and store secrets outside source control.
- Protect endpoint credentials using Windows-provided secret protection and restrictive file/IPC permissions.
- Give each component only the privileges its collectors require. Avoid running the session helper with administrator rights.
- Audit enrollment, credential revocation, role changes, configuration changes, and sensitive administrative actions.
- Document backup/restore procedures and verify a restore before customer pilots. Backup retention and deletion behavior must be disclosed before launch.
- Require signed installers and verified update packages before external customer deployment. Initially use manually deployed versioned releases; automatic updates are deferred.
- Commercial readiness also requires customer offboarding/deletion, administrator MFA, vulnerability handling, and a documented support process.

## 9. Milestones and acceptance gates

### M0 — Local vertical slice in Kali

Deliver one reproducible Compose setup in Kali, PostgreSQL migrations, a bootstrapped Product Owner account, Product Owner organization/key management, Go API, React device/report views, and a Go telemetry simulator using the intended enrollment and ingestion contracts. The existing Windows machine is used for the real agent in M1.

Acceptance:

1. A documented command starts the local stack on a clean Kali development environment with prerequisites installed.
2. The Product Owner creates two test organizations, provisions their initial administrators, and allocates endpoint enrollment keys. Organization administrators cannot create organizations or issue keys.
3. The simulator redeems an allocated key, receives device credentials, and submits heartbeats, application intervals, browser intervals, and service observations. Used, expired, and revoked keys are rejected; concurrent redemption produces at most one device and the key cannot redirect enrollment to another organization.
4. The dashboard shows deterministic expected summaries and prominently labels all simulated devices/data.
5. Replaying a batch does not change totals; unauthenticated uploads are rejected.
6. One organization cannot read or write another organization's records, including key metadata and by guessing identifiers. The Product Owner's provisioning permissions do not grant employee-activity access.
7. Database data survives container restart and a backup can be restored.

This milestone validates the server/reporting flow. It does not validate real endpoint collection or resource consumption.

### M1 — Real Windows application and service monitoring

Deliver the service, user-session helper, device credentials, bounded offline queue, foreground/idle/lock collection, service inventory/status, collection schedule, and visible employee status.

Acceptance:

1. The existing Windows machine installs the agent, redeems a Product Owner-allocated organization key, and reports through the Kali-hosted API over HTTPS. Document VM networking and firewall configuration so Windows can reach the API while PostgreSQL stays private.
2. A controlled app-switch/idle/lock/suspend script produces the expected timeline without overlapping active time.
3. A known service state change appears in the dashboard and reconciliation recovers a deliberately missed change.
4. A 30-minute network outage followed by reconnect recovers queued events without duplicates.
5. Queue-full, restart, clock-change, helper-missing, and credential-revocation scenarios show correct behavior and coverage status.
6. An eight-hour reference workload meets or documents deviations from the performance targets.

### M2 — Real browser monitoring

Deliver Chrome/Edge extensions, secure local transport, active-browser correlation, hostname-only persistence, and extension coverage indicators.

Acceptance:

1. Switching tabs and navigating within an active tab produces correct hostname intervals.
2. Background tabs, unfocused browser windows, locked sessions, and idle time do not accumulate website activity.
3. Paths, query strings, page titles, credentials, and page content are absent from persisted records and logs.
4. Missing/restarted extensions and excluded private browsing produce visible coverage limitations.
5. Combined native-agent and browser overhead is measured and published in the pilot report.

### M3 — Controlled commercial pilot

Deliver the CherrySecurity Agent signed installer/uninstaller, branded CherrySecurity Console, managed rollout instructions, tested upgrades and rollback, MFA, customer offboarding/deletion, restore runbook, retention cleanup, and support documentation. Resolve domain/name availability and trademark review before public commercial launch.

Run a declared load test, for example 100 simulated devices with one-minute batched uploads and a documented event rate, on recorded server hardware. Publish throughput, ingestion latency, report latency, storage growth, errors, and resource usage. Set a supported pilot capacity from the evidence; 100 simulated devices is a test scenario, not a capacity promise.

Acceptance includes successful installation/uninstall, an upgrade retaining device identity and queued records, rollback compatibility, cross-organization isolation, verified restore, and no unresolved critical collection/data-loss defects.

## 10. Explicitly deferred

- Linux/macOS employee agents, Firefox, and concurrent multi-session Windows support.
- Screenshots, keylogging, clipboard capture, page content, webcam/audio recording, remote shell, and remote desktop control.
- Website blocking, application blocking, service management, and automated employee scoring.
- Detailed all-process resource attribution and network inspection.
- Billing, subscriptions, self-service customer onboarding, SSO, HR integrations, and automatic updates.
- High availability, multi-region deployments, and large-scale distributed ingestion.

## 11. Risks and validation decisions

| Risk or unknown | Planned response |
| --- | --- |
| Kali-only testing hides Windows integration problems | Use simulated telemetry only in M0; require a real Windows endpoint for M1 |
| Browser extension coverage varies by policy/browser | Validate managed installation and expose missing coverage in M2 |
| Agent exceeds memory/CPU expectations | Benchmark early on low-spec hardware and profile before adding features |
| Unknown employee counts | Bound ingestion, measure a declared workload, and set supported capacity from results |
| Duplicate/offline events distort reports | Stable event IDs, durable acknowledgement, explicit gaps, and deterministic report checks |
| Monitoring captures more information than intended | Minimize fields at collection time and inspect persisted samples during acceptance |
| Service being online hides collector failure | Report service, helper, and extension health independently |

Before each milestone, resolve only the decisions needed for that step. The local topology is confirmed: Kali hosts the complete server stack, and the existing Windows machine runs the agent. Before M1, record that machine's Windows version/hardware, configure Windows-to-VM API connectivity, and choose employee identity mapping. Before M3, choose production hosting, sales regions, backup retention, and supported pilot capacity.

## 12. Definition of done for the first baby step

M0 is done when the Product Owner can start the complete local server stack in Kali, log in, create an organization and its initial administrator, allocate endpoint enrollment keys, enroll a simulated device with one of those keys, see activity/service data in the organization dashboard, retry uploads without changing totals, demonstrate role and organization isolation, and restart the stack without losing persisted data. Include setup instructions and recorded verification results. The existing Windows machine is ready for the real agent milestone M1; no real employee deployment is part of M0.
