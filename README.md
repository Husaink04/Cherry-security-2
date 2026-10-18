# CherrySecurity

Employee activity and endpoint monitoring for company-managed Windows computers.

Stack: Go backend and agent, React/TypeScript console, PostgreSQL. Kali in VMware hosts the local server stack; the Windows machine is the agent test endpoint.

## Start here

1. [Team onboarding and setup history](docs/TEAM-ONBOARDING.md) — verified environment, access, commands, decisions, and handoff status.
2. [Product requirements](docs/PRD.md) — product scope, roles, enrollment keys, milestones, and acceptance criteria.
3. [M0 verification results](docs/testing/m0-results.md) — acceptance evidence, review corrections, and limitations.
4. [Kali access checklist](docs/KALI-SETUP.md) — short access and troubleshooting reference.
5. [M1 Windows operations](docs/M1-WINDOWS-OPERATIONS.md) — native agent security boundary, build, install, enrollment, status, removal, and gated verification.
6. [M1 verification results](docs/testing/m1-results.md) — passed source checks, unsigned artifact status, and pending deployment/endpoint gates.

Current stage: Kali runs the M1 server build from `main` with database schema version 4: the native-agent contract (migration 003), PostgreSQL row-level security (migration 004), login rate limits, the organization Overview and audit log, and one-step tenant creation. The agent TLS ingress, certificates and firewall changes (the rest of Batch B) are not deployed, and no native agent is installed. Kali SSH is started manually when needed and is not enabled at boot. Preserve unrelated Kali containers and all database volumes, and deploy only committed code whose schema version matches the migrations you intend to run.

## Development commands

Run in Kali after SSH access is configured:

```sh
python3 /home/husain/cherrysecurity-m0/scripts/prepare-env.py
docker compose --project-directory /home/husain/cherrysecurity-m0 up -d --build
docker compose --project-directory /home/husain/cherrysecurity-m0 run --rm --entrypoint /app/admin api
```

The last command is a one-time interactive Product Owner bootstrap. Enter credentials locally; there is no default password. If a terminal predates Docker-group membership, run `newgrp docker` or open a fresh login first.

The [API contract](docs/api-m0.md) documents roles, routes, payloads, limits, and development constraints. The [deployment guide](docs/M0-DEVELOPMENT.md) covers synchronization, tunnels, testing, and backups.

Keep the onboarding runbook and verification status current as work proceeds. Never put passwords, enrollment secrets, private SSH keys, or backup contents in documentation or Git.
