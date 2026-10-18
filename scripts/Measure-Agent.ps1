[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string] $ManifestPath,
    [Parameter(Mandatory)] [string] $OutputPath,
    [TimeSpan] $Duration = ([TimeSpan]::FromHours(8)),
    [ValidateRange(5, 300)] [int] $SampleSeconds = 60,
    [switch] $ValidateOnly
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

if (-not [System.IO.Path]::IsPathFullyQualified($ManifestPath)) { throw 'Manifest path must be absolute.' }
if (-not [System.IO.Path]::IsPathFullyQualified($OutputPath)) { throw 'Output path must be absolute.' }
if ($Duration.TotalMinutes -lt 1 -or $Duration.TotalHours -gt 8) { throw 'Duration must be between one minute and eight hours.' }
$manifest = Get-Content -Raw -LiteralPath $ManifestPath | ConvertFrom-Json
$expectedInstall = [System.IO.Path]::Combine([Environment]::GetFolderPath([Environment+SpecialFolder]::ProgramFiles), 'CherrySecurity')
$expectedData = [System.IO.Path]::Combine([Environment]::GetFolderPath([Environment+SpecialFolder]::CommonApplicationData), 'CherrySecurity')
if ($manifest.service_name -cne 'CherrySecurityAgent' -or $manifest.install_directory -cne $expectedInstall -or $manifest.data_directory -cne $expectedData -or $manifest.binaries.Count -ne 3) { throw 'Manifest scope is invalid.' }
$allowedNames = @('CherrySecurityAgent.exe', 'CherrySecurityHelper.exe', 'CherrySecurityControl.exe')
$observedNames = @()
$installRoot = [System.IO.Path]::GetFullPath($expectedInstall + [System.IO.Path]::DirectorySeparatorChar)
foreach ($binary in $manifest.binaries) {
    $name = [System.IO.Path]::GetFileName([string]$binary.path)
    if ([string]$binary.sha256 -cnotmatch '^[0-9a-f]{64}$' -or -not [System.IO.Path]::IsPathFullyQualified([string]$binary.path) -or $allowedNames -cnotcontains $name) { throw 'Manifest binary is invalid.' }
    if (-not [System.IO.Path]::GetFullPath([string]$binary.path).StartsWith($installRoot, [StringComparison]::OrdinalIgnoreCase)) { throw 'Manifest binary escapes the install directory.' }
    $observedNames += $name
}
if (@($observedNames | Sort-Object -Unique).Count -ne 3) { throw 'Manifest binary names must be unique.' }
if ($ValidateOnly) {
    [pscustomobject]@{ status = 'validated'; duration_seconds = [int]$Duration.TotalSeconds; sample_seconds = $SampleSeconds; mutation = $false }
    exit 0
}

$outputDirectory = [System.IO.Path]::GetDirectoryName($OutputPath)
if (-not [System.IO.Directory]::Exists($outputDirectory)) { [System.IO.Directory]::CreateDirectory($outputDirectory) | Out-Null }
if ([System.IO.File]::Exists($OutputPath)) { throw 'Measurement output already exists.' }

function Get-AgentSnapshot {
    param($Manifest)
    $items = @()
    foreach ($binary in $Manifest.binaries | Where-Object { [System.IO.Path]::GetFileName([string]$_.path) -in @('CherrySecurityAgent.exe', 'CherrySecurityHelper.exe') }) {
        $process = @(Get-Process | Where-Object { $_.Path -and [string]::Equals($_.Path, [string]$binary.path, [StringComparison]::OrdinalIgnoreCase) })
        if ($process.Count -ne 1) { throw "Expected one process for $($binary.path)." }
        $hash = (Get-FileHash -Algorithm SHA256 -LiteralPath $process[0].Path).Hash.ToLowerInvariant()
        if ($hash -cne [string]$binary.sha256) { throw 'Running binary hash changed during measurement.' }
        $cim = Get-CimInstance -ClassName Win32_Process -Filter "ProcessId=$($process[0].Id)"
        $items += [pscustomobject]@{
            name = [System.IO.Path]::GetFileName($process[0].Path)
            id = $process[0].Id
            cpu_seconds = [double]$process[0].CPU
            private_bytes = [int64]$process[0].PrivateMemorySize64
            read_bytes = [int64]$cim.ReadTransferCount
            write_bytes = [int64]$cim.WriteTransferCount
        }
    }
    return $items
}

function Get-DataBytes {
    param([string] $Path)
    if (-not [System.IO.Directory]::Exists($Path)) { return [int64]0 }
    return [int64](Get-ChildItem -LiteralPath $Path -File -Recurse | Measure-Object -Property Length -Sum).Sum
}

$started = [DateTime]::UtcNow
$deadline = $started.Add($Duration)
$processors = [Environment]::ProcessorCount
$initial = @(Get-AgentSnapshot -Manifest $manifest)
$initialAdapters = Get-NetAdapterStatistics
$initialReceived = [int64]($initialAdapters | Measure-Object -Property ReceivedBytes -Sum).Sum
$initialSent = [int64]($initialAdapters | Measure-Object -Property SentBytes -Sum).Sum
$samples = [System.Collections.Generic.List[object]]::new()
do {
    $now = [DateTime]::UtcNow
    $current = @(Get-AgentSnapshot -Manifest $manifest)
    $samples.Add([pscustomobject]@{ at = $now.ToString('o'); processes = $current; data_bytes = Get-DataBytes -Path $manifest.data_directory })
    if ($now -lt $deadline) { Start-Sleep -Seconds ([Math]::Min($SampleSeconds, [Math]::Ceiling(($deadline - $now).TotalSeconds))) }
} while ([DateTime]::UtcNow -lt $deadline)
$finished = [DateTime]::UtcNow
$final = @(Get-AgentSnapshot -Manifest $manifest)
$finalAdapters = Get-NetAdapterStatistics
$finalReceived = [int64]($finalAdapters | Measure-Object -Property ReceivedBytes -Sum).Sum
$finalSent = [int64]($finalAdapters | Measure-Object -Property SentBytes -Sum).Sum
$allProcessSamples = @($samples | ForEach-Object { $_.processes })
$summary = foreach ($start in $initial) {
    $end = $final | Where-Object id -eq $start.id
    if ($null -eq $end) { throw "Process $($start.id) changed during measurement." }
    [pscustomobject]@{
        name = $start.name
        id = $start.id
        average_cpu_percent = [Math]::Round((($end.cpu_seconds - $start.cpu_seconds) / ($finished - $started).TotalSeconds / $processors) * 100, 4)
        peak_private_bytes = [int64](($allProcessSamples | Where-Object id -eq $start.id | Measure-Object -Property private_bytes -Maximum).Maximum)
        read_bytes = $end.read_bytes - $start.read_bytes
        write_bytes = $end.write_bytes - $start.write_bytes
    }
}
$result = [pscustomobject]@{
    started_at = $started.ToString('o')
    finished_at = $finished.ToString('o')
    elapsed_seconds = [Math]::Round(($finished - $started).TotalSeconds, 3)
    logical_processors = $processors
    processes = $summary
    final_data_bytes = Get-DataBytes -Path $manifest.data_directory
    host_adapter_received_bytes = $finalReceived - $initialReceived
    host_adapter_sent_bytes = $finalSent - $initialSent
    network_scope = 'host delta during measurement; not attributable to CherrySecurity alone'
    sample_count = $samples.Count
}
[System.IO.File]::WriteAllText($OutputPath, ($result | ConvertTo-Json -Depth 6), [System.Text.UTF8Encoding]::new($false))
$result
