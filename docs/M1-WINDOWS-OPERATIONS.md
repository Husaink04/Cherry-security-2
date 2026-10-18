# CherrySecurity M1 Windows operations

This runbook covers the M1 source artifacts and the later, separately approved Windows installation. The M1 agent is transparent to the selected employee: an unelevated tray icon shows the collection notice and current health. The LocalService process has no desktop window. Neither component hides processes, blocks Task Manager, prevents an administrator from stopping the service, or reinstalls deleted resources.

## Security boundary

- `CherrySecurityAgent` runs as `NT AUTHORITY\LocalService`, owns the device credential, policy, queue, service inventory, heartbeat, and HTTPS delivery.
- `CherrySecurityHelper` runs only in the selected interactive user's logon session. It sends executable basenames, idle/lock state, and session boundaries through an authenticated local named pipe.
- The pipe ACL includes SYSTEM, administrators, the service SID, and the selected user SID. On each connection the service verifies the helper's user, active console session and logon SID. The helper binds the server through the Service Control Manager: the pipe's server PID must equal the PID the SCM reports for the running `CherrySecurityAgent` service. A standard user cannot open a LocalService process to inspect its token or image path; only the SCM starts that process, and only administrators can change its binary or account.
- The helper and status notice receive no device token. Enrollment is accepted only from an elevated administrator through the separate local enrollment pipe, whose ACL grants SYSTEM, administrators and the service's own SID (the service needs that entry to accept connections).
- The agent does not collect window titles, command lines, document or input contents, screenshots, clipboard data, audio, or video.
- An HTTP 401 from the configured certificate-verified server changes the service to revoked and stops collection without deleting or replacing the credential. TLS and network failures retain the credential and queued events.

## Build

The reproducible project command is:

```sh
bash /home/husain/cherrysecurity-m0/scripts/build-agent.sh
```

It writes three Windows x64 binaries and `SHA256SUMS` under `/home/husain/cherrysecurity-m0/artifacts/agent`. The service and helper are linked as Windows GUI processes so they do not create console windows; the control program remains a console tool for explicit administrator operations.

On Windows the same binaries can be built with the project-local toolchain (`D:\Cherry-security\artifacts\go-toolchain`) from a clean, committed tree, with `GOOS=windows GOARCH=amd64 CGO_ENABLED=0`, `-trimpath -buildvcs=false`, and `-ldflags "-s -w -H=windowsgui"` for the service and helper. Build each release into a new folder under `artifacts\agent` with its `SHA256SUMS` and the source commit; the 2026-10-18 Batch C install used `artifacts\agent\batch-c5` built from `5e5c246`, then was upgraded in place to `artifacts\agent\batch-c6` built from `fec4c6e`.

The current M1 artifacts are unsigned development builds. Use them only on the approved local test endpoint. A commercial release must use the organization's protected code-signing process, timestamp signatures, publish signer identity and hashes, and verify those signatures before installation or upgrade.

## Installation plan and install

Batch C approval is required before running either install command. Use the actual artifact and CA paths from the approved manifest; do not put an enrollment key on a command line.

```powershell
& 'D:\Cherry-security\artifacts\agent\CherrySecurityControl-m1.exe' --action plan --endpoint 'https://192.168.193.129:8443' --user-sid 'SELECTED_USER_SID' --service 'D:\Cherry-security\artifacts\agent\CherrySecurityAgent-m1.exe' --helper 'D:\Cherry-security\artifacts\agent\CherrySecurityHelper-m1.exe' --control 'D:\Cherry-security\artifacts\agent\CherrySecurityControl-m1.exe' --ca 'D:\Cherry-security\artifacts\agent\agent-ca.crt'
```

After reviewing that exact JSON plan, rerun the same command from an elevated console with `--action install`. Installation refuses an existing service, scheduled task, install directory, data directory, changed source hash, reparse-point source, or non-HTTPS endpoint. It creates only the resources in the displayed plan, and any failure rolls back everything it created; the error names the failing tool and quotes its output. The helper task starts at the selected user's next sign-in if that user is not signed in during installation.

## Upgrade

To replace the binaries of an installed agent while keeping its enrollment, credential, queue, configuration and ACLs, run the new build's control program from an elevated console in its build folder:

```powershell
& 'D:\Cherry-security\artifacts\agent\batch-cN\CherrySecurityControl-m1.exe' --action upgrade --service 'D:\Cherry-security\artifacts\agent\batch-cN\CherrySecurityAgent-m1.exe' --helper 'D:\Cherry-security\artifacts\agent\batch-cN\CherrySecurityHelper-m1.exe' --control 'D:\Cherry-security\artifacts\agent\batch-cN\CherrySecurityControl-m1.exe'
```

It refuses to run from the install folder, or when the service, helper task or `agent.json` is missing, and it prints the old and new SHA-256 of each binary before changing anything. It then ends the helper task, stops the service, swaps each binary through a hash-verified `.new` copy while keeping the previous file as `.old`, starts the service, and requires it to still be running after 10 seconds. Any failure after the service stops restores the previous binaries and restarts the service. On success the `.old` files are removed and the helper task is started. The endpoint and CA are not changed by an upgrade; changing them still needs an uninstall and a fresh install.

The service is delayed automatic under LocalService. Crash recovery is restart after 10, 30, and 60 seconds, then no action, with a one-day reset. Recovery is disabled for orderly non-crash stops, so an administrator stop remains effective. Authenticated users can query service status but cannot start, stop, delete, or reconfigure it.

## Enrollment

After installation, use an elevated console. The control program disables console echo while the administrator enters the key:

```powershell
& 'C:\Program Files\CherrySecurity\CherrySecurityControl.exe' --action enroll --config 'C:\Program Files\CherrySecurity\agent.json'
```

The service validates the key with the scoped HTTPS endpoint, protects the returned credential with DPAPI under LocalService, and creates the queue only in `C:\ProgramData\CherrySecurity`. Do not paste keys, tokens, passwords, or private certificates into chat, logs, documentation, shell history, Git, or test fixtures.

## Status and administrator lifecycle

The selected employee sees `CherrySecurity Agent` in the notification area and can click it to read the collection notice and health. There is no employee stop or uninstall control.

An elevated administrator can use Windows Service Control Manager to stop or start `CherrySecurityAgent`. The scheduled helper does not restart the service. To uninstall while preserving the queue, credential, CA, and logs by default, run the control program from its build folder:

```powershell
& 'D:\Cherry-security\artifacts\agent\batch-c6\CherrySecurityControl-m1.exe' --action uninstall
```

Uninstall refuses, before changing anything, when it is run from the install folder, because a running program cannot delete itself. It waits up to 15 seconds for an exiting helper to release its executable, removes `.new`/`.old` leftovers of an interrupted upgrade, and is safe to repeat. Deleting `C:\ProgramData\CherrySecurity` requires the separate affirmative `--delete-data` flag. Uninstall refuses reparse-point paths and removes only the fixed CherrySecurity service, task, known binaries, configuration, and known data files; unexpected files make directory removal fail instead of being recursively deleted.

## Verification gates

Batch A proves source validation, Windows compilation, deterministic state/queue tests, current-user DPAPI, and current-user pipe authentication. It does not prove LocalService DPAPI, another-user denial, real lock/suspend notifications, installed task/service ACLs, real tray behavior, TLS to Kali, or CPU/RAM/disk targets.

Batch B (Kali migration, TLS files, ingress and listener) and Batch C (installation and enrollment on the owner's Windows 11 PC) are complete; see the M1 results for what was and was not observed. Batch D must approve assisted activity, lock/suspend, crash/outage/revocation, and eight-hour resource tests.
