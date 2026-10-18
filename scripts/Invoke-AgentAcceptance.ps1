[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string] $ManifestPath,
    [ValidateSet('Validate', 'AdminStop', 'CrashRecovery', 'TestServiceLifecycle')] [string] $Mode = 'Validate',
    [switch] $Execute
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Read-ValidatedManifest {
    param([string] $Path)
    if (-not [System.IO.Path]::IsPathFullyQualified($Path)) { throw 'Manifest path must be absolute.' }
    $manifest = Get-Content -Raw -LiteralPath $Path | ConvertFrom-Json
    $programFiles = [Environment]::GetFolderPath([Environment+SpecialFolder]::ProgramFiles)
    $programData = [Environment]::GetFolderPath([Environment+SpecialFolder]::CommonApplicationData)
    $expected = @{
        service_name = 'CherrySecurityAgent'
        task_name = 'CherrySecurity Session Helper'
        install_directory = [System.IO.Path]::Combine($programFiles, 'CherrySecurity')
        data_directory = [System.IO.Path]::Combine($programData, 'CherrySecurity')
        test_service_name = 'CherrySecurityM1Test'
    }
    foreach ($name in $expected.Keys) {
        if ($manifest.$name -cne $expected[$name]) { throw "Manifest has an invalid $name." }
    }
    if ($manifest.binaries.Count -ne 3) { throw 'Manifest must contain exactly three binaries.' }
    $allowedNames = @('CherrySecurityAgent.exe', 'CherrySecurityHelper.exe', 'CherrySecurityControl.exe')
    $observedNames = @()
    foreach ($binary in $manifest.binaries) {
        if (-not [System.IO.Path]::IsPathFullyQualified([string]$binary.path)) { throw 'Binary paths must be absolute.' }
        $binaryName = [System.IO.Path]::GetFileName([string]$binary.path)
        if ($allowedNames -cnotcontains $binaryName) { throw 'Unexpected binary in manifest.' }
		$observedNames += $binaryName
        if ([string]$binary.sha256 -cnotmatch '^[0-9a-f]{64}$') { throw 'Binary hash must be lowercase SHA-256.' }
        $expectedRoot = [System.IO.Path]::GetFullPath($expected.install_directory + [System.IO.Path]::DirectorySeparatorChar)
        if (-not [System.IO.Path]::GetFullPath([string]$binary.path).StartsWith($expectedRoot, [StringComparison]::OrdinalIgnoreCase)) { throw 'Binary escapes the install directory.' }
    }
	if (@($observedNames | Sort-Object -Unique).Count -ne 3) { throw 'Manifest binary names must be unique.' }
    return $manifest
}

function Get-VerifiedAgentProcess {
    param($Manifest, [string] $FileName)
    $entry = @($Manifest.binaries | Where-Object { [System.IO.Path]::GetFileName([string]$_.path) -ceq $FileName })
    if ($entry.Count -ne 1) { throw "Manifest entry missing for $FileName." }
    $processes = @(Get-Process | Where-Object { $_.Path -and [string]::Equals($_.Path, [string]$entry[0].path, [StringComparison]::OrdinalIgnoreCase) })
    if ($processes.Count -ne 1) { throw "Expected exactly one running $FileName process." }
    $actual = (Get-FileHash -Algorithm SHA256 -LiteralPath $processes[0].Path).Hash.ToLowerInvariant()
    if ($actual -cne [string]$entry[0].sha256) { throw "$FileName hash does not match the approved manifest." }
    return $processes[0]
}

$manifest = Read-ValidatedManifest -Path $ManifestPath
if ($Mode -eq 'Validate') {
    [pscustomobject]@{ status = 'validated'; mode = $Mode; mutation = $false; service = $manifest.service_name; task = $manifest.task_name }
    exit 0
}
if (-not $Execute) { throw 'Mutating acceptance modes require the explicit -Execute switch and prior Batch D approval.' }
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'An elevated administrator console is required.' }

switch ($Mode) {
    'AdminStop' {
        Stop-Service -Name $manifest.service_name
        Start-Sleep -Seconds 70
        $service = Get-Service -Name $manifest.service_name
        if ($service.Status -ne 'Stopped') { throw 'Administrative stop was reversed.' }
        [pscustomobject]@{ status = 'passed'; mode = $Mode; service_status = [string]$service.Status }
    }
    'CrashRecovery' {
        $process = Get-VerifiedAgentProcess -Manifest $manifest -FileName 'CherrySecurityAgent.exe'
        Stop-Process -Id $process.Id -Force
        $deadline = [DateTime]::UtcNow.AddSeconds(20)
        do {
            Start-Sleep -Milliseconds 500
            $service = Get-Service -Name $manifest.service_name
        } until ($service.Status -eq 'Running' -or [DateTime]::UtcNow -ge $deadline)
        if ($service.Status -ne 'Running') { throw 'Service did not recover after the approved crash.' }
        [pscustomobject]@{ status = 'passed'; mode = $Mode; previous_pid = $process.Id }
    }
    'TestServiceLifecycle' {
        $sc = [System.IO.Path]::Combine([Environment]::SystemDirectory, 'sc.exe')
        $command = [System.IO.Path]::Combine([Environment]::SystemDirectory, 'cmd.exe') + ' /c exit 0'
        & $sc create $manifest.test_service_name 'binPath=' $command 'start=' 'demand' | Out-Null
        if ($LASTEXITCODE -ne 0) { throw 'Could not create the scoped test service.' }
        try {
            Start-Sleep -Seconds 2
            & $sc query $manifest.test_service_name | Out-Null
            if ($LASTEXITCODE -ne 0) { throw 'Scoped test service was not queryable.' }
        } finally {
            & $sc delete $manifest.test_service_name | Out-Null
            if ($LASTEXITCODE -ne 0) { throw 'Could not delete the scoped test service.' }
        }
        [pscustomobject]@{ status = 'passed'; mode = $Mode; test_service = $manifest.test_service_name }
    }
}
