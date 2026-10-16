# CherrySecurity — Team onboarding and setup runbook

Last verified: 2026-10-16. This records observed facts separately from planned deployment. Read the PRD for requirements and the M0 plan for implementation detail.

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
| Working Windows-to-Kali address | `10.22.21.102` on TCP port 22 |
| Other observed IPv4 addresses | `10.6.6.1`, `172.17.0.1`; not used for project access |
| Configured VM resources | Four vCPUs, 4096 MB RAM |
| Observed guest memory | 3879 MiB total, approximately 1614 MiB available at initial check |
| Observed root filesystem | 75 GB total, approximately 34 GB available at initial check |
| Docker Engine | `28.5.2+dfsg4` |
| Docker Compose | `2.40.3-3` |
| SSH service | Active; startup enablement is **disabled** |
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
11. Found existing guest containers and recorded that they must be preserved. SSH is currently running but is not enabled to start automatically at boot.

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
ssh -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes -i "$env:USERPROFILE\.ssh\cherrysecurity_kali_ed25519" husain@10.22.21.102
```

For a noninteractive connectivity check:

```powershell
ssh -o BatchMode=yes -o ConnectTimeout=10 -o StrictHostKeyChecking=yes -o IdentitiesOnly=yes -i "$env:USERPROFILE\.ssh\cherrysecurity_kali_ed25519" husain@10.22.21.102 'whoami; hostname; docker info --format "{{.ServerVersion}}"'
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
- **Timeout:** Confirm the VM is powered on, rediscover its IP with `hostname -I`, and inspect the current VM network/firewall. No router forwarding or VMware network-mode change was needed for the verified connection.
- **Host identity changed:** Compare `sudo ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub` from Kali's console before updating known hosts.
- **Public-key permission denied:** Check the intended username, chosen private-key path, guest `authorized_keys` entry, ownership, and permissions. Do not send private keys or passwords through chat.
- **Docker socket permission denied:** Confirm approved membership with `id`; open a new SSH session after the owner changes groups. Do not make `/var/run/docker.sock` world-writable.
- **`ssh-keyscan` fails with unsupported KEX:** The current Windows keyscan utility produced `unsupported KEX method sntrup761x25519-sha512@openssh.com`. Normal Windows `ssh` successfully negotiated the connection. For diagnosis, `ssh -v -o KexAlgorithms=curve25519-sha256 -o HostKeyAlgorithms=ssh-ed25519 ...` displayed the fingerprint; host verification remained enabled.

Do not run `docker system prune`, stop unrelated containers, overwrite SSH configuration, or delete volumes to troubleshoot this project.

## 7. Planned application deployment — not yet performed

- Keep source editable in the Windows workspace and synchronize a dedicated deployment copy into Kali. The deployment directory is not created yet.
- Use a dedicated Compose project name, proposed `cherrysecurity-m0`, isolated from existing workloads. Do not use global container cleanup commands.
- Run the Go API, database, migrations, simulator, and React hosting inside Kali. Do not run a duplicate backend/database on Windows.
- Keep PostgreSQL and API private on the Compose network; expose the web service on guest loopback `127.0.0.1:8080` after checking that the port is available.
- Initially use SSH forwarding from Windows. Once the web listener exists, the planned command is:

  ```powershell
  ssh -N -o ExitOnForwardFailure=yes -o StrictHostKeyChecking=yes -o IdentitiesOnly=yes -i "$env:USERPROFILE\.ssh\cherrysecurity_kali_ed25519" -L 127.0.0.1:8080:127.0.0.1:8080 husain@10.22.21.102
  ```

  Then open `http://127.0.0.1:8080` on Windows. **This is a future access URL, not a running application today.** If the Windows port is occupied, choose a different local forwarding port and record it.

- Bootstrap the Product Owner with an interactively entered password. Customer organization users and device credentials are separate from Kali SSH accounts.
- No application secrets, database volume, migration, container image, or deployed CherrySecurity service exists yet. Implementation will pin runtime versions and dependencies.
- Assess available memory during builds because this VM also runs unrelated containers. Do not resize the VM or shut down other workloads automatically.

## 8. Current status and next action

| Work | Status |
| --- | --- |
| PRD and brand requirements | Written; owner reviewed and requested incorporated revisions |
| M0 implementation plan | Written; explicit plan review/execution-method selection pending |
| VMware discovery and host-to-guest reachability | Verified |
| SSH host verification and key authorization | Verified |
| Docker/Compose installation and daemon access | Verified |
| Backend / React / PostgreSQL deployment | Not started |
| M0 acceptance tests / backup restore | Not run |
| Real Windows monitoring agent | Later milestone |

Next: review the M0 plan, confirm execution inline or delegated, then build Task 1's isolated healthy stack. Infrastructure readiness does not establish product readiness.

## 9. Documentation maintenance

After each completed setup or implementation step, record what changed, commands needed to reproduce it, verification results, and remaining blockers here or in the linked milestone test report. Update this status table and the root README when deployment begins. Record version changes and actual guest paths rather than leaving future commands marked as completed.

Keep passwords, private keys, session tokens, enrollment secrets, and backup contents out of all documents. Share this environment-specific runbook through the team's controlled repository; it contains internal addresses and machine paths.
