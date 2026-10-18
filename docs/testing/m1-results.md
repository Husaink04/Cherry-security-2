# CherrySecurity M1 verification results

Last updated 2026-10-18. This report distinguishes source checks already observed from deployment and endpoint checks that require separate approval. It is not a security certification.

| Check | Observed result |
| --- | --- |
| Agent module integrity | `go mod verify` passed with the project-local Go 1.27.2 toolchain |
| Windows agent tests | `go test ./... -count=1` passed, including policy, timeline, bounded durable queue, delivery trust, current-user DPAPI, current-user pipe authentication, collectors, helper-loss gaps, configuration, ACL construction, and installer planning |
| Static checks | `go vet ./...` and `git diff --check` passed |
| Go vulnerability scan | Official `govulncheck@v1.9.0 ./...` completed on 2026-10-18 and reported no reachable vulnerabilities |
| Linux portability | The platform-neutral `internal/agent` package compiled for `linux/amd64`; Linux race execution remains pending because Kali SSH is intentionally stopped and Windows race instrumentation requires a C compiler |
| Windows artifacts | Three `windows/amd64` binaries built under `D:\Cherry-security\artifacts\agent`; a SHA-256 manifest was generated and Authenticode reported all three as `NotSigned`, as expected for local development |
| Backend native contract | Full backend suite passed with the race detector against a throwaway PostgreSQL 17 as the restricted cherryapp role (19 tests, including the two-tenant isolation matrix and row-level security without tenant filters); go vet and gofmt clean |
| Console | 18 frontend unit tests, TypeScript check and production build passed; the owner confirmed sign-in, Overview, audit log and one-step tenant creation on Kali; Playwright acceptance has not run on this build |
| Kali deployment | main deployed 2026-10-18: schema 2 → 4 in one migration transaction after a verified backup; readiness 200 through nginx and the SSH tunnel |
| Agent TLS ingress | Live on `192.168.193.129:8443` with a private ECDSA P-256 CA and an IP-only 30-day server certificate (expires 2026-11-17); from Kali, a Go client on Windows and Windows `curl.exe`: 401 without a device token, 404 for other routes, 405 for wrong methods, TLS 1.3, untrusted CAs rejected; no firewall change |
| Scope validation | Acceptance and measurement scripts validate fixed CherrySecurity service/task/directory names, absolute paths, three expected binary names, and lowercase SHA-256 values before any mutating mode |

Generated binaries are ignored by Git. Their current hashes are recorded in `D:\Cherry-security\artifacts\agent\SHA256SUMS`; rebuilds intentionally change that local manifest. They are unsuitable for customer deployment until code signing and release verification are designed and approved.

Batch B is complete: the database backup, migrations 003 and 004, private TLS material, and the agent ingress on the verified NAT address are in place, and no firewall change was needed. The server certificate must be renewed before 2026-11-17. Batch C is pending: selected-user SID, elevation, service/task/directories, LocalService DPAPI, another-user denial, enrollment, real tray, and installed ACL checks. Batch D is pending: foreground/idle/lock/suspend/service observations, helper termination, crash and administrator-stop behavior, bounded outage/retry, revocation, and the real eight-hour CPU/RAM/disk measurement.

Current known limits: no browser-domain collection (M2), no concurrent-session support, no production signing, no real endpoint performance evidence, and no live TLS path. Host-wide network adapter totals in the measurement script are context only and cannot be attributed solely to CherrySecurity; CPU, private bytes, process I/O, and CherrySecurity data size are process/scoped measurements.

Implementation decisions and exact limitations are in [the M1 ledger](M1-LEDGER.md). Build, installation, enrollment, status, and removal behavior are in [the M1 Windows operations guide](../M1-WINDOWS-OPERATIONS.md).
