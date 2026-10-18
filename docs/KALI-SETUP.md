# CherrySecurity — Kali access for M0

Updated 2026-10-16. Full setup history, connection commands, teammate access, and deployment status are in [Team onboarding](TEAM-ONBOARDING.md).

## Current observations

- VMware Workstation is installed and running on Windows.
- One running VM was listed: `C:\Users\husai\Documents\Virtual Machines\Kali\Kali.vmx`.
- Its configuration lists four virtual CPUs and 4096 MB memory. Guest checks reported 3879 MiB total memory and approximately 34 GB free on the root filesystem.
- VMware's guest-IP lookup failed; this does not establish that the network is broken.
- Windows-to-Kali SSH key access is verified as `husain@192.168.193.129`, with the guest host fingerprint verified against its console.
- Guest OS is Kali Rolling 2026.3, x86_64. Docker Engine 28.5.2+dfsg4 and Compose 2.40.3-3 are installed; daemon access works as `husain` after approved Docker-group membership.
- SSH is stopped by owner choice and disabled at boot. Existing unrelated containers are running and must be preserved.

## Initial access procedure (completed; reference for repeat setup)

1. Open the running Kali VM in VMware and log in yourself.
2. In its terminal run these read-only checks and share the output:

   ```sh
   whoami
   hostname -I
   systemctl is-active ssh
   docker --version
   docker compose version
   ```

3. SSH is intentionally stopped. Start it in Kali only after the owner explicitly approves restarting it:

   ```sh
   sudo systemctl start ssh
   ```

   Enter your sudo password in Kali yourself. If SSH is missing or a command fails, share the error; prerequisite installation will be adapted to the guest's actual packages.

4. When a dedicated SSH public key is prepared, authorize that public key for your Kali account. Keep private keys and passwords out of chat. Verify the guest SSH host fingerprint from the VM console before trusting the first connection.

## Deployment approach

- Keep the source workspace on Windows and synchronize a deployment copy into a dedicated Kali directory after access is established.
- Build and run backend, React hosting, database, migrations, and simulator inside Kali.
- Keep the database private to the container network.
- Reach the console through SSH forwarding to Kali's loopback web listener; commands are in the operations guide.
- The owner approved switching the VM adapter to NAT (VMnet8) after the original bridged route failed. Current address: `192.168.193.129`. No router port forwarding is configured.
- Use a locally entered Product Owner password during bootstrap. No default commercial credentials.
- Keep Kali powered on during deployment/testing. Later, M1 will require your help installing/testing the real agent on Windows.

## Current deployment

SSH and Docker access were verified before SSH was stopped by owner choice. The dedicated stack remains deployed at `/home/husain/cherrysecurity-m0`, schema version 2. The real Product Owner was created interactively. Automated backend, browser, fresh-install, and backup/restore checks passed; see [M0 results](testing/m0-results.md). Existing unrelated workloads were preserved. M1 source exists only on Windows and has not been synchronized or deployed.
