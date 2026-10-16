# CherrySecurity

Employee activity and endpoint monitoring for company-managed Windows computers.

Stack: Go backend and agent, React/TypeScript console, PostgreSQL. Kali in VMware hosts the local server stack; the Windows machine is the agent test endpoint.

## Start here

1. [Team onboarding and setup history](docs/TEAM-ONBOARDING.md) — verified environment, access, commands, decisions, and handoff status.
2. [Product requirements](docs/PRD.md) — product scope, roles, enrollment keys, milestones, and acceptance criteria.
3. [M0 implementation plan](docs/superpowers/plans/2026-10-16-m0.md) — proposed implementation tasks and verification.
4. [Kali access checklist](docs/KALI-SETUP.md) — short access and troubleshooting reference.

Current stage: infrastructure access verified; product implementation has not started. There is no CherrySecurity application, Compose stack, database schema, or console URL yet. Existing containers in Kali belong to other workloads and must be preserved.

Keep the onboarding runbook and verification status current as work proceeds. Never put passwords, enrollment secrets, private SSH keys, or backup contents in documentation or Git.
