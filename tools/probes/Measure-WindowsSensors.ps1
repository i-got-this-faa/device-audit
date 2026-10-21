#requires -Version 7.0
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$OutputPath,
    [ValidateRange(1, 30)][int]$Samples = 3,
    [ValidateRange(1, 300)][int]$IntervalSeconds = 15,
    [ValidateRange(1, 30)][int]$TimeoutSeconds = 10
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
. "$PSScriptRoot/WindowsProbe.ps1"
if (-not $IsWindows) { throw 'Windows is required; no fixture fallback is provided.' }
$fullOutput = [IO.Path]::GetFullPath($OutputPath)
if (Test-Path -LiteralPath $fullOutput) { throw 'Output already exists; choose a new path.' }
if (-not (Test-Path -LiteralPath ([IO.Path]::GetDirectoryName($fullOutput)) -PathType Container)) {
    throw 'Output parent directory must exist.'
}
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
$elevated = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$identity.Dispose()
$os = Get-CimInstance Win32_OperatingSystem -Property Caption,Version,BuildNumber,OSArchitecture -OperationTimeoutSec 3
$machine = Get-CimInstance Win32_ComputerSystem -Property Model,NumberOfLogicalProcessors -OperationTimeoutSec 3
$cpu = @(Get-CimInstance Win32_Processor -Property Name -OperationTimeoutSec 3 | ForEach-Object { $_.Name })
$adapters = @(Get-CimInstance Win32_VideoController -Property Name,DriverVersion -OperationTimeoutSec 3 | ForEach-Object {
    @{ model = $_.Name; driver_version = $_.DriverVersion }
})
$report = [ordered]@{
    schema_version = 'device-audit.windows-probe.v1'
    purpose = 'development_source_availability_and_probe_cost_only'
    started_at = [DateTime]::UtcNow.ToString('o')
    environment = @{
        os = $os.Caption; version = $os.Version; build = $os.BuildNumber; architecture = $os.OSArchitecture
        model = $machine.Model; processors = $cpu; logical_processors = $machine.NumberOfLogicalProcessors
        display_adapters = $adapters; elevated = $elevated; powershell = $PSVersionTable.PSVersion.ToString()
        context = 'interactive_token_not_service_qualification'
    }
    samples = $Samples; interval_seconds = $IntervalSeconds; timeout_seconds = $TimeoutSeconds
    sweeps = @()
}
for ($sample = 0; $sample -lt $Samples; $sample++) {
    $sweepTimer = [Diagnostics.Stopwatch]::StartNew()
    $results = @()
    foreach ($source in 'cpu', 'memory', 'disk', 'network', 'battery', 'thermal', 'gpu', 'events') {
        $results += Invoke-IsolatedProbe -Source $source -TimeoutMilliseconds ($TimeoutSeconds * 1000)
    }
    $elapsed = $sweepTimer.Elapsed.TotalMilliseconds
    $report.sweeps += @{
        index = $sample; elapsed_ms = [math]::Round($elapsed, 3)
        cadence_overrun = $elapsed -gt $IntervalSeconds * 1000; sources = $results
    }
    Write-Host "Sweep $($sample + 1)/$Samples finished in $([math]::Round($elapsed)) ms."
    if ($sample -lt $Samples - 1 -and $elapsed -lt $IntervalSeconds * 1000) {
        Start-Sleep -Milliseconds ([int]($IntervalSeconds * 1000 - $elapsed))
    }
}
$report.completed_at = [DateTime]::UtcNow.ToString('o')
# CreateNew prevents accidental overwrites, including a race after the initial check.
$stream = [IO.File]::Open($fullOutput, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write)
try {
    $bytes = [Text.Encoding]::UTF8.GetBytes(($report | ConvertTo-Json -Depth 12))
    $stream.Write($bytes)
} finally { $stream.Dispose() }
Write-Host "Saved local evidence: $fullOutput"
