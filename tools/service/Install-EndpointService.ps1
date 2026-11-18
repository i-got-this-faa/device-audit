#requires -Version 7.0
<#
.SYNOPSIS
Installs endpoint-agent as the DeviceAuditEndpoint Windows service (TEL02 #26).

.DESCRIPTION
Development and qualification install, not the signed release installer (#57).
Run it elevated. It copies the agent to Program Files, creates the service as
NT AUTHORITY\LocalService with an unrestricted per-service SID, restricts the
token to SeChangeNotifyPrivilege, configures restart-on-failure, and prepares:

  <Root>\service.json   service config, readable by the service
  <Root>\sampling.json  optional sampling config copy
  <Root>\evidence       signed evidence, service.log and sampling reports
  <Root>\enrollment     CA file and the one-use bootstrap file
  <Root>\identity       created by the service itself with its private DACL

-BootstrapFile is moved, not copied, into the protected enrollment directory.
The service deletes it as soon as it reads it.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$AgentPath,
    [string]$Root = (Join-Path $env:ProgramData 'DeviceAudit\Endpoint'),
    [string]$InstallDir = (Join-Path $env:ProgramFiles 'DeviceAudit'),
    [string]$EnrollmentOrigin,
    [string]$CAFile,
    [string]$BootstrapFile,
    [string]$SamplingConfig,
    [ValidateRange(1048576, 1073741824)][long]$MaxEvidenceBytes = 64MB,
    [ValidateRange(1, 86400)][int]$RestartDelaySeconds = 60,
    [ValidateSet('Automatic', 'Manual')][string]$StartType = 'Automatic'
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$name = 'DeviceAuditEndpoint'
$sid = "NT SERVICE\$name"
function Invoke-Native([string]$Program, [string[]]$Arguments) {
    $out = & $Program @Arguments 2>&1
    if ($LASTEXITCODE -ne 0) { throw "$Program $($Arguments -join ' ') failed ($LASTEXITCODE): $out" }
}

$principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Run this installer elevated.' }
if (Get-Service -Name $name -ErrorAction SilentlyContinue) { throw "$name is already installed; run Uninstall-EndpointService.ps1 first." }
if (($EnrollmentOrigin -or $BootstrapFile) -and -not ($EnrollmentOrigin -and $BootstrapFile)) { throw 'Enrollment needs both -EnrollmentOrigin and -BootstrapFile.' }

$null = New-Item -ItemType Directory -Force -Path $InstallDir
$exe = Join-Path $InstallDir 'endpoint-agent.exe'
Copy-Item -LiteralPath $AgentPath -Destination $exe -Force

# The service SID only resolves once the service exists, so create it first.
$config = Join-Path $Root 'service.json'
$binPath = "`"$exe`" --service --service-config `"$config`""
$start = if ($StartType -eq 'Automatic') { 'auto' } else { 'demand' }
Invoke-Native sc.exe @('create', $name, 'binPath=', $binPath, 'obj=', 'NT AUTHORITY\LocalService', 'start=', $start, 'DisplayName=', 'Device Audit endpoint collector')
Invoke-Native sc.exe @('description', $name, 'Samples endpoint telemetry and signs it with the admitted device identity (TEL02 #26).')
Invoke-Native sc.exe @('sidtype', $name, 'unrestricted')
Invoke-Native sc.exe @('privs', $name, 'SeChangeNotifyPrivilege')
$delay = $RestartDelaySeconds * 1000
Invoke-Native sc.exe @('failure', $name, 'reset=', '86400', 'actions=', "restart/$delay/restart/$delay/restart/$delay")
# Treat a non-zero service exit code as a failure, so recovery actions run.
Invoke-Native sc.exe @('failureflag', $name, '1')

# Root: administrators and SYSTEM only, plus traverse/read and create-folder
# on the root itself so the service can create its private identity directory.
$evidence = Join-Path $Root 'evidence'
$enrollment = Join-Path $Root 'enrollment'
$null = New-Item -ItemType Directory -Force -Path $Root, $evidence, $enrollment
Invoke-Native icacls.exe @($Root, '/inheritance:r', '/grant:r', 'SYSTEM:(OI)(CI)F', 'BUILTIN\Administrators:(OI)(CI)F', "${sid}:(RX,AD)")
Invoke-Native icacls.exe @($evidence, '/grant', "${sid}:(OI)(CI)M")
Invoke-Native icacls.exe @($enrollment, '/grant', "${sid}:(OI)(CI)M")

$enrollmentConfig = $null
if ($EnrollmentOrigin) {
    $caPath = $null
    if ($CAFile) {
        $caPath = Join-Path $enrollment 'ca.pem'
        Copy-Item -LiteralPath $CAFile -Destination $caPath -Force
    }
    $bootstrapPath = Join-Path $enrollment 'bootstrap.json'
    Move-Item -LiteralPath $BootstrapFile -Destination $bootstrapPath -Force
    # A moved file keeps its old DACL; reset it to the directory's.
    Invoke-Native icacls.exe @($bootstrapPath, '/reset')
    $enrollmentConfig = [ordered]@{ origin = $EnrollmentOrigin; ca_file = $caPath; bootstrap_file = $bootstrapPath }
}
$samplingPath = $null
if ($SamplingConfig) {
    $samplingPath = Join-Path $Root 'sampling.json'
    Copy-Item -LiteralPath $SamplingConfig -Destination $samplingPath -Force
    Invoke-Native icacls.exe @($samplingPath, '/grant', "${sid}:R")
}
[ordered]@{
    schema_version     = 'device-audit.endpoint-service.v1'
    state_dir          = (Join-Path $Root 'identity')
    evidence_dir       = $evidence
    max_evidence_bytes = $MaxEvidenceBytes
    sampling_config    = $samplingPath
    enrollment         = $enrollmentConfig
} | ConvertTo-Json | Set-Content -LiteralPath $config -Encoding utf8NoBOM
Invoke-Native icacls.exe @($config, '/grant', "${sid}:R")
Write-Host "Installed $name ($StartType) as NT AUTHORITY\LocalService; config $config"
