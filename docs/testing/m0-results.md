# CherrySecurity M0 verification results

Verified 2026-10-16 against the Kali deployment and Windows console tests. Scope: server, console, persistence, and explicitly simulated telemetry. This is acceptance evidence, not a security certification.

| Check | Observed result |
| --- | --- |
| Go dependencies, race suite, vet | `go mod verify`, `go test -race -count=1 -v ./...`, and `go vet ./...` passed; application tests completed in 117.123 seconds |
| Authentication and isolation | Negative tests cover missing/invalid sessions, CSRF/origin, role boundaries, cross-tenant identifiers, malformed inputs, and revoked credentials |
| Enrollment and ingestion | Single-use enrollment, concurrency, atomic invalid batches, identical replay, conflicting IDs, overlap rejection, timezone boundaries, and retention tests passed |
| Frontend | Six unit tests passed; TypeScript check and Vite production build passed |
| Browser acceptance | Four Edge/Playwright tests passed against Kali, including owner provisioning, organization reports, replay/revocation, invalid login, delayed issuance race, and missing sequence coverage |
| Responsive layout | Desktop and mobile report screenshots inspected; mobile overflow assertion passed |
| Backup and restore | All nine table fingerprints and index definitions matched a new isolated restored database; fixture included revoked devices, used keys, events, and summaries |
| Fresh installation | New Compose project with independent secrets/volumes passed readiness, schema version 2, zero initial accounts, and non-superuser runtime-role checks |
| Bootstrap CLI | Automated PTY test using real runtime database permissions passed in an isolated test database |
| Real Product Owner | Human supplied CLI success output; actual database contained one account, unchanged after database/API/web restart; readiness returned HTTP 200 |
| npm audit | Full and production dependency audits reported zero vulnerabilities at verification time |
| Go vulnerability check | `govulncheck@v1.9.0 -show verbose ./...` exited zero, with no affected imported packages or reachable vulnerabilities |
| Container build | Backend and frontend images built successfully; backend build asserts private fixture/environment files are absent from its context |

Browser acceptance used `cherryapp`, the same restricted runtime database role as the real API, against the separate `cherrysecurity_test` database. Synthetic credentials remain in ignored private fixture files. No real owner password was supplied to automated tests or stored in source. Dedicated browser-test services were stopped afterward.

The Go vulnerability scan also reported module advisory `GO-2026-5932` in the unused, unmaintained `golang.org/x/crypto/openpgp` package, with no fixed version listed. CherrySecurity imports bcrypt from that module and does not import openpgp. This remains a module-level advisory, not a clean bill of health for every package in the dependency graph.

Review corrections were verified with failing-then-passing regressions: aggregate totals remain complete beyond 1,000 breakdown rows; cleanup advances an irreversible ingestion watermark before removing replay evidence; organization selection is disabled while a key issuance is pending; missing sequence counts appear in endpoint coverage. Race instrumentation uses longer test timeouts while production retains its normal timeout and password-hashing cost.

Runtime versions observed: Go 1.27.2, PostgreSQL 17, Node 24, React 19.3.1, TypeScript 7.0.2, Vite 8.3.4, Docker Engine 28.5.2+dfsg4, Compose 2.40.3-3. Dependency versions are locked; base-image tags require normal maintenance and are not an immutable supply-chain attestation.

Preserved verification resources include fresh project `cherrysecurity-m0-fresh-926b44a0`, restore database `cherrysecurity_restore_7779d20f2af3_test`, and CLI database `cherrysecurity_cli_d89c6b6a06_test`. Fresh-project services are stopped; volumes and private environment files are retained. No global cleanup or unrelated-container shutdown was performed.

Remaining limits: no real Windows service/helper, browser extension, installer/signing, native credential-storage validation, agent CPU/RAM/disk measurements, commercial-scale load testing, MFA/SSO/account recovery, or production deployment assessment. Collection schedule and idle settings are stored for later collectors; synthetic M0 input does not demonstrate enforcement on Windows. Development HTTP is restricted to loopback SSH forwarding; production requires HTTPS and secure cookies. M1 and deployment changes require separately approved scope.

Reproduction commands and handling of sensitive test artifacts: [operations guide](../M0-DEVELOPMENT.md). Implementation decisions: [execution ledger](M0-LEDGER.md).
