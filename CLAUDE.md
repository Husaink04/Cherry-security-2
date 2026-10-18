# CherrySecurity project rules

These rules add to the global rules in `~/.claude/CLAUDE.md` and take precedence where they are stricter.

## Approval before any change

- Never create, update, rename, move, or delete anything in this project without my explicit approval in chat first. That covers source, docs, configs, scripts, branches, commits, Docker containers/volumes, database schema or data, certificates, and Windows services/tasks.
- Before asking, show the exact paths, commands, and a summary or diff. One approval covers only that action.
- Read-only inspection and existing tests that write nothing outside caches or temp directories need no approval.
- Milestone gates still apply: Batch B (Kali migration/TLS/ingress), Batch C (Windows install/enrollment), and Batch D (assisted collection/benchmarks) each need their own separate approval. See [docs/testing/M1-LEDGER.md](docs/testing/M1-LEDGER.md).
- Kali SSH stays stopped unless I say otherwise. Preserve unrelated Kali containers and all database volumes. Never run `docker system prune`, delete volumes, or bypass host-key or TLS verification.

## Security standard

This is a monitoring product that handles employee activity data, device credentials, and multi-tenant organization data. Hold every change to the OWASP Top 10 (2025) and ASVS as described in the global rules, plus these project specifics:

- **Tenant isolation:** every org-scoped query filters by the caller's `organization_id`. Check device ownership before returning or changing a device (no IDOR).
- **Auth:** keep the session-cookie model (HttpOnly, SameSite=Strict, server-side expiry) and the CSRF + Origin checks on non-GET requests. Store only hashes of session, CSRF, device, and enrollment tokens.
- **SQL:** pgx parameterized queries only; never build SQL strings from input.
- **Input:** keep strict JSON decoding (unknown fields rejected, body size limits) and allow-list validation of every event field. Keep the full-URL ban for browser events.
- **Privacy:** collect no window titles, command lines, document/input contents, screenshots, clipboard, audio, or video. Respect retention limits and the ingest watermark.
- **Agent:** keep the LocalService least-privilege model, DPAPI-protected credentials, authenticated named pipes with SID/session checks, certificate-verified HTTPS only, and the reparse-point and exclusive-create checks in install/uninstall. The agent must stay visible to the employee and stoppable by administrators.
- **Supply chain:** pin exact Go, npm, and container image versions; verify checksums; add no new dependencies without approval.
- **Secrets:** never commit or print `.env`, `secrets/`, keys, certificates, enrollment keys, tokens, passwords, or backups.
- **Errors and logging:** return generic client errors; audit security-relevant actions with `audit()`; never log secrets or personal activity data.
- **Tests:** add regression tests for authorization, validation, and failure paths with every security-relevant change.
