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
| SSH service | Stopped by owner choice; startup enablement is **disabled** |
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

## 8. Current status and next action

| Work | Status |
| --- | --- |
| PRD and brand requirements | Written; owner reviewed and requested incorporated revisions |
| M0 implementation plan | Approved and executed inline; decisions recorded in the ledger |
| VMware discovery and host-to-guest reachability | Verified |
| SSH host verification and key authorization | Verified |
| Docker/Compose installation and daemon access | Verified |
| Backend / React / PostgreSQL deployment | Running, schema version 2 |
| M0 acceptance tests / backup restore | Passed; see linked verification report |
| Actual Product Owner | Created interactively; database count verified |
| M1 Windows agent source | Service/helper/control source and unsigned local artifacts built on branch `m1`; see M1 results |
| Real Windows monitoring agent | Not installed; Batch C approval is still required |

Use the [M0 operations guide](M0-DEVELOPMENT.md), [M0 results](testing/m0-results.md), [M1 Windows operations guide](M1-WINDOWS-OPERATIONS.md), and [M1 results](testing/m1-results.md). M1 deployment and endpoint acceptance remain separately approved batches.

## 9. Documentation maintenance

After each completed setup or implementation step, record what changed, commands needed to reproduce it, verification results, and remaining blockers here or in the linked milestone test report. Update this status table and the root README when deployment begins. Record version changes and actual guest paths rather than leaving future commands marked as completed.

Keep passwords, private keys, session tokens, enrollment secrets, and backup contents out of all documents. Share this environment-specific runbook through the team's controlled repository; it contains internal addresses and machine paths.
