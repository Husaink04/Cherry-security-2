# M0 execution ledger

Plan: `D:\Cherry-security\docs\superpowers\plans\2026-10-16-m0.md`.

- 2026-10-16: User approved the complete M0 change scope and supplied repository `https://github.com/Husaink04/Cherry-security-2`.
- Work happens inline on new feature branch `m0` in the explicitly approved, previously unversioned workspace. No additional worktree is needed for an empty repository with no existing branch or product code.
- Ruling: Keep a tracked ledger here rather than deleting scratch evidence; user explicitly requested enduring team documentation. No unrelated files or guest workloads will be removed.
- Preflight: Task 2 authentication feeds Tasks 3/5/6. Device credentials from Task 3 feed Task 4 and simulator in Task 5. Event IDs/types from Task 4 feed reports/replay. Same-origin proxy from Task 1 feeds CSRF/auth in Tasks 2/6. Backup in Task 7 verifies all persisted records. Contracts remain aligned with PRD v0.3.
- Ruling: Consolidate the small backend into `backend/internal/app` with feature-specific files rather than adding store/httpapi wrapper layers. Preserve the API and transactional isolation contracts.
- Infrastructure: SSH verified, Docker permissions verified, existing unrelated workloads preserved. Kali SSH is active but not enabled at boot.
- Task 1 complete: reproducible Compose stack, private API/database, non-root containers, readiness and schema compatibility. Initial health test failed before implementation and passed afterward.
- Tasks 2–3 complete: interactive owner bootstrap, sessions/CSRF/roles, organization provisioning, hashed single-use keys, transactional enrollment, and revocation.
- Tasks 4–5 complete: validated atomic telemetry ingestion, idempotent replay, coverage, timezone-aware summaries, retention, and persistent fixture simulator.
- Task 6 complete: React owner/organization console, responsive reporting, visible simulated data and missing coverage, one-time secrets, and bounded report warnings.
- Tasks 7–8 complete: operating documentation, backup/isolated restore, fresh deployment, race-enabled integration tests, browser acceptance, and dependency checks. See [results](m0-results.md).
- Explicit infrastructure approval: owner switched Kali to NAT (VMnet8) after the bridged route failed. New IP `192.168.193.129`; SSH identity reverified. Unrelated workloads preserved.
- Read-only implementation review identified report totals truncated by the breakdown limit, historical replay after retention increases, and organization switching during key issuance. Each was reproduced with a failing regression, corrected, and verified passing. Sequence-gap coverage was also made visible and tested.
- Ruling: database schema version 2 adds a persistent ingestion watermark so deleting raw deduplication evidence cannot reopen expired history. Report aggregates are independent of the 1,000-row breakdown limit.
- Ruling: retain production bcrypt cost 12 and request timeout 12 seconds. Race-instrumented tests use a longer timeout to avoid mistaking instrumentation overhead for an authentication failure.
- Ruling: use feature-specific files within the existing small app package, maintain a tracked ledger, and preserve test evidence rather than introducing wrapper layers or deleting resources.
- Dependency result: no affected imported Go packages; one advisory exists in unused `x/crypto/openpgp`. Do not describe the entire module graph as advisory-free.
- Human provided the actual bootstrap success line; fresh SQL confirmed exactly one real account. Its contents and database/API/web readiness survived a service restart.
