# CherrySecurity — Team onboarding and setup runbook

Last verified: 2026-10-18. M0 is deployed and verified; M1 source is under development and is not installed. Read the PRD and milestone verification reports before changing either environment.

## 1. Project and current milestone

CherrySecurity is a commercial employee activity and endpoint monitoring product. Its first endpoint platform is Windows. The Product Owner creates customer organizations, provisions their initial administrators, and allocates organization-bound, single-use endpoint enrollment keys.

- Backend and native agent: Go.
- Console: React and TypeScript.
- Central data store: PostgreSQL.
- Local hosting: Docker Compose inside Kali Linux in VMware Workstation.
- Windows endpoint collection is M1; browser extensions are M2.
- M0 builds the server/console and explicitly simulated endpoint activity. It does not install a real monitoring agent.

See [PRD v0.3](PRD.md) and [M0 plan](superpowers/plans/2026-10-16-m0.md).

## 2. Environment inventory

| Item | Verified value |
| --- | --- |
| Windows source workspace | `D:\Cherry-security` |
| VMware Workstation directory | `C:\Program Files (x86)\VMware\VMware Workstation` |
| Kali VM definition | `C:\Users\husai\Documents\Virtual Machines\Kali\Kali.vmx` |
| Guest OS / architecture | Kali GNU/Linux Rolling 2026.3 / x86_64 |
| Guest hostname / login | `kali` / `husain` |
| Working Windows-to-Kali address | `192.168.193.129` on TCP port 22, VMware NAT (VMnet8) |
| Other observed IPv4 addresses | `10.6.6.1`, `172.17.0.1`; not used for project access |
| Configured VM resources | Four vCPUs, 4096 MB RAM |
| Observed guest memory | 3879 MiB total, approximately 1614 MiB available at initial check |
| Observed root filesystem | 75 GB total, approximately 34 GB available at initial check |
| Docker Engine | `28.5.2+dfsg4` |
| Docker Compose | `2.40.3-3` |
| SSH service | Started manually by the owner when needed (`sudo systemctl start ssh`); startup enablement is **disabled** |
| Docker permissions | `husain` belongs to `docker`; daemon access verified from a fresh SSH connection |

IP addresses, free resources, versions, usernames, and paths are specific to this development environment. Recheck them on a new machine or after VM/network changes. The VM has existing running containers unrelated to CherrySecurity; no existing containers or data have been changed by this setup.

## 3. Setup history and reasons

1. Inspected the workspace: documentation only, with no application code or Git repository.
2. Located VMware Workstation and the running Kali VM using `vmrun list`.
3. Tried `vmrun getGuestIPAddress`; it failed to return an address. Used the guest terminal to discover the address instead.
4. The first `hostname -i` returned `127.0.1.1`, a loopback address. Uppercase `hostname -I` returned the guest interface addresses. Windows successfully reached `10.22.21.102`.
5. The owner started SSH in Kali with `sudo systemctl start ssh` and confirmed `active`.
6. Verified installed Docker and Compose versions; no installation was necessary.
7. The owner read the guest's ED25519 host-key fingerprint in the VM console. Compared it with the actual Windows SSH handshake; it matched before the host was trusted.
8. Generated a dedicated Windows SSH key and the owner appended its **public** half to the guest user's `~/.ssh/authorized_keys`. The private half remains on Windows.
9. Verified passwordless SSH as `husain`. Inspected OS, memory, disk, and Docker access using read-only commands.
10. Docker daemon access initially failed with a socket permission error. The owner ran `sudo usermod -aG docker husain`. A fresh SSH connection confirmed group membership and successful Docker daemon access.
11. Found existing guest containers and recorded that they must be preserved. SSH was not enabled to start automatically at boot.
12. The original bridged connection later timed out in both directions although SSH was listening. The owner explicitly approved and applied VMware NAT (VMnet8). Verified the same SSH host identity at `192.168.193.129`; no certificate or host-key verification was bypassed.
13. Deployed the dedicated Compose stack, applied two migrations, completed automated acceptance and restore tests, and bootstrapped the actual Product Owner through the guest terminal. Passwords were entered locally and were not stored in source.
14. During M1 source work, the owner explicitly chose to keep Kali SSH stopped. Windows source checks use the approved project-local Go toolchain; no M1 deployment has been synchronized to Kali.
15. On 2026-10-18 the owner started SSH and approved deploying `main` (`14a0145`). The database was backed up (`backups/cherrysecurity-20261018T123437Z-*.dump`, checked with `pg_restore --list`) and the previous images were tagged `:m0-rollback`. A `git archive` of `main` was synced, which excludes uncommitted work. `migrate`, `api` and `web` were rebuilt, and migrations 003 and 004 were applied in one transaction. Verified results: schema 4, seven tables with forced row-level security, a no-login `cherry_auth` role, a restricted `cherryapp` that sees no rows without a tenant scope, readiness 200, and a console sign-in the owner confirmed.
16. Later on 2026-10-18 the agent HTTPS ingress was deployed. `agent-ingress` runs `nginxinc/nginx-unprivileged:1.28-alpine` as `1000:1000` (so it can read the mode-600 key without extra capabilities) and listens only on `192.168.193.129:8443`; `AGENT_BIND_IP=192.168.193.129` was added to `.env`. `scripts/prepare-agent-tls.py` created a private ECDSA P-256 CA (expires 2027-10-18, SHA-256 fingerprint `45:F4:3C:14:62:61:25:5D:E5:0D:50:89:B6:D5:62:14:83:07:83:80:14:15:07:0C:F7:2D:7B:82:61:A0:7C:61`) and a 30-day server certificate for that IP only (expires 2026-11-17) in `secrets/agent-tls` (directories 700, files 600). A first Ed25519 set is kept in `secrets/agent-tls-ed25519-20261018`; Windows Schannel cannot negotiate Ed25519. Verified from Kali, with a Go client on Windows and with Windows `curl.exe`: the policy route returns 401 without a device token, other routes 404, wrong methods 405, TLS 1.3, and untrusted CAs are rejected. The console port 8080 and PostgreSQL are not reachable from Windows. No firewall change was needed. The public CA copy for installation is `D:\Cherry-security\artifacts\agent\agent-ca.crt`.
17. On 2026-10-18 the owner approved Batch C on this Windows 11 Pro PC for user `husain\husai` (SID `S-1-5-21-4178743217-2586328297-2924519820-1001`). Installs ran in an administrator PowerShell, some through a UAC prompt the owner approved, with output logged under `artifacts\agent`. Four failed attempts each rolled back cleanly and led to the fixes recorded in the M1 ledger. The final build `artifacts\agent\batch-c5` (commit `5e5c246`) is installed and enrolled with an owner-issued key; the first enrolled device was revoked before reinstalling. After a Kali reboot all CherrySecurity containers, including `agent-ingress`, came back without intervention, but SSH and the console tunnel had to be restarted.

## 4. SSH identity and connection

Verified Kali ED25519 host fingerprint:

```text
SHA256:WlVyiQrIbl5eQLxbTlX6wPsg4YAnz3A81/SwDshAgPA
```

Existing Windows developer key location:

```text
C:\Users\husai\.ssh\cherrysecurity_kali_ed25519
```

That is a private-key **path**, not a file to copy into the repository or distribute to teammates. Every new teammate should create and authorize their own key, ideally with their own guest account when ongoing shared development begins.

On the current Windows account, connect from PowerShell:

```powershell
ssh -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes -i "$env:USERPROFILE\.ssh\cherrysecurity_kali_ed25519" husain@192.168.193.129
```

For a noninteractive connectivity check:

```powershell
ssh -o BatchMode=yes -o ConnectTimeout=10 -o StrictHostKeyChecking=yes -o IdentitiesOnly=yes -i "$env:USERPROFILE\.ssh\cherrysecurity_kali_ed25519" husain@192.168.193.129 'whoami; hostname; docker info --format "{{.ServerVersion}}"'
```

Success means the command exits zero and shows `husain`, `kali`, and the Docker server version. Do not disable host-key verification to make a failed connection work.

## 5. New teammate access

1. Ask the environment owner to provision/approve a guest account and required permissions. The current `husain` account is the initial development account, not a shared credential distribution mechanism.
2. Generate a personal key on the teammate's Windows machine. Use a unique filename; never overwrite an existing key:

   ```powershell
   ssh-keygen -t ed25519 -f "$env:USERPROFILE\.ssh\cherrysecurity_kali_ed25519" -C "your-name-cherrysecurity"
   ```

   Choose a passphrase when prompted. Share only the resulting `.pub` public key with the environment owner.

3. The environment owner appends that public key as one line to the intended guest account's `~/.ssh/authorized_keys`, preserving existing entries. Set directory permission 700 and file permission 600.
4. Verify the guest host fingerprint through the VM console or the environment owner before accepting the first connection. A future legitimate host-key change requires re-verification, not blind acceptance of this historical value.
5. Connect with the teammate's account/key and run the read-only checks in section 6. On departure, remove that teammate's public-key authorization and revoke their application access separately.

Docker-group membership grants root-equivalent control of the guest. Restrict it to trusted developers; it is unrelated to customer organization roles in CherrySecurity.

## 6. Useful checks and troubleshooting

In Kali:

```sh
whoami
hostname -I
systemctl is-active ssh
systemctl is-enabled ssh
id
docker --version
docker compose version
docker info --format '{{.ServerVersion}}'
free -m
df -h /
```

- **Connection refused after reboot:** Open Kali locally and run `sudo systemctl start ssh`. Boot startup is currently disabled. The owner may choose to enable it later with `sudo systemctl enable ssh`; that has not been done during this setup.
- **Timeout:** Confirm the VM is powered on and rediscover its IP with `hostname -I`. This installation now uses the explicitly approved NAT adapter. Verify host identity before changing connection addresses; further network changes require approval.
- **Host identity changed:** Compare `sudo ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub` from Kali's console before updating known hosts.
- **Public-key permission denied:** Check the intended username, chosen private-key path, guest `authorized_keys` entry, ownership, and permissions. Do not send private keys or passwords through chat.
- **Docker socket permission denied:** Confirm approved membership with `id`; open a new SSH session after the owner changes groups. Do not make `/var/run/docker.sock` world-writable.
- **`ssh-keyscan` fails with unsupported KEX:** The current Windows keyscan utility produced `unsupported KEX method sntrup761x25519-sha512@openssh.com`. Normal Windows `ssh` successfully negotiated the connection. For diagnosis, `ssh -v -o KexAlgorithms=curve25519-sha256 -o HostKeyAlgorithms=ssh-ed25519 ...` displayed the fingerprint; host verification remained enabled.

Do not run `docker system prune`, stop unrelated containers, overwrite SSH configuration, or delete volumes to troubleshoot this project.

## 7. Running application

- Source remains in `D:\Cherry-security`; the deployed copy is `/home/husain/cherrysecurity-m0`.
- Compose project `cherrysecurity-m0` runs PostgreSQL, the Go API, and React hosting. Migrations run as a separate one-shot service. The simulator is invoked explicitly; it collects no real activity.
- PostgreSQL and API remain private on the Compose network. The web service binds guest loopback `127.0.0.1:8080`.
- Windows reaches the console through SSH forwarding:

  ```powershell
  ssh -N -o ExitOnForwardFailure=yes -o StrictHostKeyChecking=yes -o IdentitiesOnly=yes -i "$env:USERPROFILE\.ssh\cherrysecurity_kali_ed25519" -L 127.0.0.1:8080:127.0.0.1:8080 husain@192.168.193.129
  ```

  Open `http://127.0.0.1:8080` on Windows while the verified tunnel is running. Check for an existing tunnel before launching another.

- The initial Product Owner exists. Sign in using the email and password entered during bootstrap. Bootstrap refuses to overwrite an existing owner. Customer users and device credentials remain separate from Kali SSH accounts.
- Database data persists in a project-owned volume; private environment credentials remain in the guest's ignored mode-600 `.env`. Never remove the volume or publish this file.
- Assess available memory during builds because this VM also runs unrelated containers. Do not resize the VM or shut down other workloads automatically.
- Windows `curl.exe` uses Schannel, which cannot check revocation for the private agent CA; add `--ssl-no-revoke` together with `--cacert D:\Cherry-security\artifacts\agent\agent-ca.crt` when inspecting `https://192.168.193.129:8443`.
- After a VM reboot the API may restart once while PostgreSQL starts; that is expected. nginx looks up the API again within 10 seconds, so the console recovers without a manual restart.
- Rollback point for the 2026-10-18 deployment: the backup above plus the `cherrysecurity-m0-{api,migrate,web}:m0-rollback` images. Restoring over the live database is a manual, separately approved step; `scripts/restore.sh` restores only into a new test database.

## 8. Current status and next action

| Work | Status |
| --- | --- |
| PRD and brand requirements | Written; owner reviewed and requested incorporated revisions |
| M0 implementation plan | Approved and executed inline; decisions recorded in the ledger |
| VMware discovery and host-to-guest reachability | Verified |
| SSH host verification and key authorization | Verified |
| Docker/Compose installation and daemon access | Verified |
| Backend / React / PostgreSQL deployment | Running `main`, schema version 4 with row-level security |
| Agent TLS ingress (rest of Batch B) | Running on `192.168.193.129:8443`; server certificate expires 2026-11-17, renew by retiring `secrets/agent-tls` and rerunning `scripts/prepare-agent-tls.py` |
| M0 acceptance tests / backup restore | Passed; see linked verification report |
| Actual Product Owner | Created interactively; database count verified |
| M1 Windows agent source | On `main`; installed build `artifacts\agent\batch-c5` from `5e5c246` (unsigned); see M1 results |
| Real Windows monitoring agent | Installed and enrolled on the owner's PC for `husain\husai`; helper healthy and uploading. Batch D (activity, lock/suspend, outage, revocation, eight-hour measurement) still requires approval |

Use the [M0 operations guide](M0-DEVELOPMENT.md), [M0 results](testing/m0-results.md), [M1 Windows operations guide](M1-WINDOWS-OPERATIONS.md), and [M1 results](testing/m1-results.md). M1 deployment and endpoint acceptance remain separately approved batches.

## 9. Documentation maintenance

After each completed setup or implementation step, record what changed, commands needed to reproduce it, verification results, and remaining blockers here or in the linked milestone test report. Update this status table and the root README when deployment begins. Record version changes and actual guest paths rather than leaving future commands marked as completed.

Keep passwords, private keys, session tokens, enrollment secrets, and backup contents out of all documents. Share this environment-specific runbook through the team's controlled repository; it contains internal addresses and machine paths.
