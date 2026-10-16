# CherrySecurity — Kali access for M0

Updated 2026-10-16. Full setup history, connection commands, teammate access, and deployment status are in [Team onboarding](TEAM-ONBOARDING.md).

## Current observations

- VMware Workstation is installed and running on Windows.
- One running VM was listed: `C:\Users\husai\Documents\Virtual Machines\Kali\Kali.vmx`.
- Its configuration lists four virtual CPUs and 4096 MB memory. Guest checks reported 3879 MiB total memory and approximately 34 GB free on the root filesystem.
- VMware's guest-IP lookup failed; this does not establish that the network is broken.
- Windows-to-Kali SSH key access is verified as `husain@10.22.21.102`, with the guest host fingerprint verified against its console.
- Guest OS is Kali Rolling 2026.3, x86_64. Docker Engine 28.5.2+dfsg4 and Compose 2.40.3-3 are installed; daemon access works as `husain` after approved Docker-group membership.
- SSH is active but disabled at boot. Existing unrelated containers are running and must be preserved.

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

3. If SSH is installed but inactive, start it in Kali:

   ```sh
   sudo systemctl start ssh
   ```

   Enter your sudo password in Kali yourself. If SSH is missing or a command fails, share the error; prerequisite installation will be adapted to the guest's actual packages.

4. When a dedicated SSH public key is prepared, authorize that public key for your Kali account. Keep private keys and passwords out of chat. Verify the guest SSH host fingerprint from the VM console before trusting the first connection.

## Deployment approach

- Keep the source workspace on Windows and synchronize a deployment copy into a dedicated Kali directory after access is established.
- Build and run backend, React hosting, database, migrations, and simulator inside Kali.
- Keep the database private to the container network.
- Initially reach the console through an SSH local forward to Kali's loopback web listener. Configure exact commands once username/IP are known.
- No router port forwarding or bridged-network change is required by default; test the existing host-to-guest route first.
- Use a locally entered Product Owner password during bootstrap. No default commercial credentials.
- Keep Kali powered on during deployment/testing. Later, M1 will require your help installing/testing the real agent on Windows.

## Not yet done

SSH access and Docker daemon permissions are verified. The owner started SSH, authorized a dedicated public key, and added `husain` to the Docker group. No guest software was installed, and no CherrySecurity application or database has been deployed. VM settings and existing workload data have not been changed. M0 plan review remains pending.
