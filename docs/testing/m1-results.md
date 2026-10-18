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
| Backend native contract | Full local backend suite and vet passed earlier against isolated schemas; live M0 remains schema 2 and migration 003 has not run |
| Console | Eight frontend unit tests, TypeScript check, and production build passed earlier; no real-device browser acceptance has run |
| TLS tooling | Certificate preflight tests and Compose parsing passed with synthetic/placeholders; no Kali CA, server key, listener, or firewall rule exists |
| Scope validation | Acceptance and measurement scripts validate fixed CherrySecurity service/task/directory names, absolute paths, three expected binary names, and lowercase SHA-256 values before any mutating mode |

Generated binaries are ignored by Git. Their current hashes are recorded in `D:\Cherry-security\artifacts\agent\SHA256SUMS`; rebuilds intentionally change that local manifest. They are unsuitable for customer deployment until code signing and release verification are designed and approved.

Batch B is pending: database backup, additive migration 003, agent ingress container, private TLS material, verified NAT binding, and any required scoped firewall rule. Batch C is pending: selected-user SID, elevation, service/task/directories, LocalService DPAPI, another-user denial, enrollment, real tray, and installed ACL checks. Batch D is pending: foreground/idle/lock/suspend/service observations, helper termination, crash and administrator-stop behavior, bounded outage/retry, revocation, and the real eight-hour CPU/RAM/disk measurement.

Current known limits: no browser-domain collection (M2), no concurrent-session support, no production signing, no real endpoint performance evidence, and no live TLS path. Host-wide network adapter totals in the measurement script are context only and cannot be attributed solely to CherrySecurity; CPU, private bytes, process I/O, and CherrySecurity data size are process/scoped measurements.

Implementation decisions and exact limitations are in [the M1 ledger](M1-LEDGER.md). Build, installation, enrollment, status, and removal behavior are in [the M1 Windows operations guide](../M1-WINDOWS-OPERATIONS.md).
