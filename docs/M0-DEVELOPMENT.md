# CherrySecurity M0 — development operations

## Source and deployment

The source of truth is `D:\Cherry-security` on Windows. Its configured Git remote is `https://github.com/Husaink04/Cherry-security-2`, working branch `m0`. Guest deployment files live at `/home/husain/cherrysecurity-m0`.

From PowerShell, synchronize tracked/development source while excluding secrets and generated frontend dependencies:

```powershell
& 'D:\Cherry-security\scripts\Sync-Kali.ps1'
```

Synchronization updates files in the dedicated guest directory; it does not delete obsolete files. Never use this script as a substitute for an intentional migration or cleanup. It does not copy `.env`, backups, private fixture credentials, local dependencies, or Git history.

On first setup in Kali:

```sh
python3 /home/husain/cherrysecurity-m0/scripts/prepare-env.py
docker compose --project-directory /home/husain/cherrysecurity-m0 up -d --build
```

`prepare-env.py` creates independent random database passwords in `.env` with owner-only permissions and refuses to replace an existing environment. Keep that file out of Git. Database credentials are consumed during initial volume initialization; changing `.env` alone does not rotate a populated database's passwords.

Runtime services use bounded log files, non-root application containers, read-only filesystems, and dropped capabilities. PostgreSQL has a persistent named volume. API/DB ports stay private; the web port is guest loopback 8080. Browser test web port 8082 exists only when that profile is started. Do not remove database volumes or run global Docker cleanup.

Go test tools use project-owned module/build cache volumes, owned by UID/GID 1000. On a fresh host, run `bash /home/husain/cherrysecurity-m0/scripts/prepare-caches.sh` before non-root tooling. This adjusts only the project's cache volumes. A cache-volume ownership warning on this original VM reflects pre-Compose cache creation, not a failed database or insecure runtime permission.

## Product Owner bootstrap

Use the Product Owner email chosen by the project owner during setup. Never include its password in a command, chat, source file, or test fixture.

In an interactive Kali terminal:

```sh
docker compose --project-directory /home/husain/cherrysecurity-m0 run --rm --entrypoint /app/admin api
```

Enter the email and a password of 14–72 bytes twice. Bootstrap refuses to replace an existing Product Owner. The Linux login, Git author email, and application login are independent identities. A terminal that was open before Docker-group membership needs `newgrp docker` or a fresh login before this command.

## Windows access

The current SSH identity is local to the original Windows account. New teammates authorize their own keys as described in [the onboarding runbook](TEAM-ONBOARDING.md).

```powershell
ssh -N -o ExitOnForwardFailure=yes -o ServerAliveInterval=30 -o ServerAliveCountMax=3 -o StrictHostKeyChecking=yes -o IdentitiesOnly=yes -i "$env:USERPROFILE\.ssh\cherrysecurity_kali_ed25519" -L 127.0.0.1:8080:127.0.0.1:8080 -L 127.0.0.1:8082:127.0.0.1:8082 husain@192.168.193.129
```

Leave the tunnel running; access the actual console at `http://127.0.0.1:8080`. Test console uses `http://127.0.0.1:8082`. If the VM's IP changes, verify its host fingerprint before updating the address. An initial background tunnel was launched from this project; its PID/logs are recorded under the ignored Windows `artifacts` directory. Do not start duplicate tunnels if a verified one already owns these ports.

## Verification commands

Backend checks run in Kali against an isolated schema inside `cherrysecurity_test`. The test suite refuses any database name not ending `_test` and drops only schemas it creates itself.

```sh
bash /home/husain/cherrysecurity-m0/scripts/test-backend.sh
docker compose --project-directory /home/husain/cherrysecurity-m0 ps
curl --fail http://127.0.0.1:8080/api/readyz
```

Frontend checks from PowerShell:

```powershell
npm.cmd --prefix D:\Cherry-security\web ci --ignore-scripts
npm.cmd --prefix D:\Cherry-security\web test
npm.cmd --prefix D:\Cherry-security\web run build
```

The frontend is built again inside its Kali container image. Windows commands also allow local type/unit checks without VM availability. Frontend package versions are locked; dependency audits must be recorded with their date and coverage, not treated as proof of overall security.

## Isolated browser fixtures

These steps affect only the dedicated test database and profile, not the real owner account:

```sh
docker compose --project-directory /home/husain/cherrysecurity-m0 run --rm tools go run ./cmd/testfixture -out /src/browser-fixture.json
docker compose --project-directory /home/husain/cherrysecurity-m0 run --rm tools sh -c 'DATABASE_URL="$TEST_DATABASE_URL" GRANT_APP_ROLE=true go run ./cmd/migrate'
docker compose --project-directory /home/husain/cherrysecurity-m0 --profile browser-test up -d api-test web-test
```

The fixture command creates a random test-owner password and writes it to a private, ignored fixture file. It refuses to overwrite credentials or an existing test owner. Reuse that file for repeat browser runs; don't reseed the owner. The migration command grants the runtime role access to the test schema; the test API uses the same restricted role as the real API. Transfer the fixture securely to the ignored Windows artifact directory:

```powershell
scp -o BatchMode=yes -o StrictHostKeyChecking=yes -o IdentitiesOnly=yes -i "$env:USERPROFILE\.ssh\cherrysecurity_kali_ed25519" husain@192.168.193.129:/home/husain/cherrysecurity-m0/backend/browser-fixture.json D:\Cherry-security\artifacts\browser-fixture.json
npm.cmd --prefix D:\Cherry-security\web exec -- playwright test --config=D:\Cherry-security\web\playwright.config.ts
```

The browser suite uses installed Microsoft Edge and generates unique synthetic organizations/admins per run. It tests both UI roles, one-time secret display, endpoint enrollment/replay, service observations, report totals, invalid login, and a mobile-width overflow check. Never commit the private fixture file, screenshots containing secrets, or generated browser output. Shut down only `api-test`/`web-test` after acceptance when no longer needed.

## Interactive telemetry simulator

Create an organization, administrator, and key in the Console first. Make a private state directory owned by the invoking guest account, then run the simulator using that account's UID/GID:

```sh
mkdir -p /home/husain/cherrysecurity-m0/secrets/simulator
chmod 700 /home/husain/cherrysecurity-m0/secrets/simulator
docker compose --project-directory /home/husain/cherrysecurity-m0 run --rm --user "$(id -u):$(id -g)" --volume /home/husain/cherrysecurity-m0/secrets/simulator:/state --entrypoint /app/simulator api
```

The key is entered through a hidden terminal prompt, not a CLI argument. Device credentials and event IDs persist in the mode-600 state file. Repeating the command replays the same events without double counting. Expected fixture totals are application 900 seconds, browser 300 seconds as a separate breakdown, and idle 120 seconds. Dates follow the reported fixture start time and the organization's timezone. The simulator does not run continuously or collect real host activity.

## Backup and restore

```sh
bash /home/husain/cherrysecurity-m0/scripts/backup.sh
bash /home/husain/cherrysecurity-m0/scripts/restore.sh /absolute/path/to/generated.dump cherrysecurity_restore_example_test
```

Backups are sensitive, restricted-permission custom-format PostgreSQL dumps. The restore script only accepts a new `cherrysecurity_restore_NAME_test` database and refuses existing targets; it never drops or overwrites the application database. Compare counts, roles, key states, revoked devices, audit records, and report totals after a restore. Do not claim verification merely because `pg_restore` exited successfully.

Additional acceptance checks, run in Kali within an approved test scope:

```sh
python3 /home/husain/cherrysecurity-m0/scripts/verify-bootstrap.py
python3 /home/husain/cherrysecurity-m0/scripts/verify-backup.py
python3 /home/husain/cherrysecurity-m0/scripts/verify-fresh.py
```

Bootstrap verification creates an isolated test database and drives the interactive CLI with synthetic credentials. Backup verification requires the populated browser-test fixtures and compares all table/index fingerprints in a new restore database. Fresh verification creates a unique Compose project, private environment, and new volumes on loopback port 8084, then stops that project. These checks preserve their test databases, environment files, and volumes for investigation; they do not overwrite the real owner or remove existing resources.

## Known local constraints

- Kali also hosts unrelated lab containers. They are outside this project's authority and were not stopped or changed.
- This host has experienced intermittent registry resets and a later loss of Windows-to-guest SSH reachability. Record actual blockers in the verification report and rediscover the guest address instead of disabling verification or changing networks blindly.
- M0 does not establish native-agent memory/CPU claims, real Windows collection, browser collection fidelity, commercial capacity, or production security certification.
