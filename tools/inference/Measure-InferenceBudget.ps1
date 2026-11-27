# Run on Windows from the repository checkout. The request is a reviewed CT03
# workload and inference bundle. Keep the output local until it is reviewed.
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Request,
    [Parameter(Mandatory)][string]$Report,
    [switch]$AttestPhysicalVictus
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
if (-not $IsWindows) { throw 'This harness requires Windows.' }
$root = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
$requestPath = (Resolve-Path -LiteralPath $Request).Path
$reportPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Report)
if (Test-Path -LiteralPath $reportPath) { throw 'Choose a new report path.' }
$computer = Get-CimInstance Win32_ComputerSystem
$cpu = @(Get-CimInstance Win32_Processor)
$build = [int](Get-CimInstance Win32_OperatingSystem).BuildNumber
$cpuName = if ($cpu.Count -eq 1) { $cpu[0].Name.Trim() } else { 'multiple CPU packages' }
$matchingTarget = ($computer.Manufacturer -eq 'HP') -and ($computer.Model -match 'Victus.*15-fb0') -and
    ($cpuName -eq 'AMD Ryzen 5 5600H with Radeon Graphics') -and ($computer.NumberOfLogicalProcessors -eq 12) -and ($build -eq 26200)
if ($AttestPhysicalVictus -and -not $matchingTarget) { throw 'Windows hardware does not match the selected physical target.' }

$temp = New-Item -ItemType Directory -Path (Join-Path ([IO.Path]::GetTempPath()) ('device-audit-inference-' + [guid]::NewGuid()))
$exe = Join-Path $temp.FullName 'endpoint-agent.exe'
$vars = @{
    DEVICE_AUDIT_INFERENCE_REQUEST = $requestPath
    DEVICE_AUDIT_INFERENCE_REPORT = $reportPath
    DEVICE_AUDIT_INFERENCE_EXE = $exe
    DEVICE_AUDIT_INFERENCE_HOST = (@{
        physical = [bool]$AttestPhysicalVictus
        cpu_model = $cpuName
        logical_processors = [int]$computer.NumberOfLogicalProcessors
        os_build_family = $build
        hardware_class = $computer.Model
    } | ConvertTo-Json -Compress)
}
$previous = @{}
foreach ($key in $vars.Keys) { $previous[$key] = [Environment]::GetEnvironmentVariable($key) }
Push-Location $root
try {
    & go build -o $exe ./apps/endpoint-agent
    if ($LASTEXITCODE -ne 0) { throw 'Endpoint build failed.' }
    foreach ($key in $vars.Keys) { [Environment]::SetEnvironmentVariable($key, $vars[$key]) }
    & go test -count=1 -timeout 31h -v -run '^TestMeasureInferenceWindows$' ./apps/endpoint-agent
    if ($LASTEXITCODE -ne 0) { throw 'Windows inference measurement failed.' }
    $previousPythonPath = $env:PYTHONPATH
    try {
        $env:PYTHONPATH = Join-Path $root 'models/src'
        & python -m device_audit_models.evaluation --policy models/evaluation/ml05-policy.json --resources $reportPath
        $gateExit = $LASTEXITCODE
    } finally {
        $env:PYTHONPATH = $previousPythonPath
    }
} finally {
    foreach ($key in $previous.Keys) { [Environment]::SetEnvironmentVariable($key, $previous[$key]) }
    Pop-Location
    Remove-Item -LiteralPath $temp.FullName -Recurse
}
exit $gateExit
