param([string]$GuestAddress = '192.168.193.129', [string]$GuestUser = 'husain')
$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
$artifactDirectory = Join-Path $projectRoot 'artifacts'
New-Item -ItemType Directory -Path $artifactDirectory -Force | Out-Null
$archivePath = Join-Path $artifactDirectory 'source.tar'
& tar.exe -cf $archivePath --exclude=.git --exclude=.env --exclude=secrets --exclude=backups --exclude=artifacts --exclude=node_modules --exclude=dist --exclude=.superpowers --exclude=simulator-state.json -C $projectRoot .
if ($LASTEXITCODE -ne 0) { throw 'Source archive failed' }
$identityPath = Join-Path $env:USERPROFILE '.ssh\cherrysecurity_kali_ed25519'
$destination = "${GuestUser}@${GuestAddress}"
& scp.exe -o BatchMode=yes -o StrictHostKeyChecking=yes -o IdentitiesOnly=yes -i $identityPath $archivePath "${destination}:/home/husain/cherrysecurity-m0/source.tar"
if ($LASTEXITCODE -ne 0) { throw 'Source transfer failed' }
& ssh.exe -o BatchMode=yes -o StrictHostKeyChecking=yes -o IdentitiesOnly=yes -i $identityPath $destination 'tar -xf /home/husain/cherrysecurity-m0/source.tar -C /home/husain/cherrysecurity-m0'
if ($LASTEXITCODE -ne 0) { throw 'Source extraction failed' }
