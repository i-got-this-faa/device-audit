#requires -Version 7.3
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

Every directory and file gets an exact protected DACL: SYSTEM and
Administrators full, plus the service SID's own right. Existing access entries
are replaced, not merged. -BootstrapFile is moved, not copied, into the
enrollment directory as the last step; the service deletes it as soon as it
reads it. Inputs are checked before the service is registered. A failure after
registration moves the credential back, removes that registration (warning if
it cannot) and keeps any existing state.
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
    [ValidateRange(1, 65536)][int]$MaxEvidenceRecords = 4096,
    [ValidateRange(1, 86400)][int]$RestartDelaySeconds = 60,
    [ValidateSet('Automatic', 'Manual')][string]$StartType = 'Automatic'
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$name = 'DeviceAuditEndpoint'
# 7.3+ passes native arguments, including binPath's embedded quotes, verbatim.
# The SCM and the service config need absolute paths.
$Root = [IO.Path]::GetFullPath($Root)
$InstallDir = [IO.Path]::GetFullPath($InstallDir)
function Invoke-Native([string]$Program, [string[]]$Arguments) {
    $out = & $Program @Arguments 2>&1
    if ($LASTEXITCODE -ne 0) { throw "$Program $($Arguments -join ' ') failed ($LASTEXITCODE): $out" }
}
# Replaces the whole DACL of Path with SYSTEM and Administrators full access
# plus the service SID's entry, and blocks inheritance from the parent.
function Set-PrivateAcl([string]$Path, [string]$ServiceAce) {
    $inherit = if (Test-Path -LiteralPath $Path -PathType Container) { 'OICI' } else { '' }
    $acl = Get-Acl -LiteralPath $Path
    $acl.SetSecurityDescriptorSddlForm("D:P(A;$inherit;FA;;;SY)(A;$inherit;FA;;;BA)$ServiceAce", 'Access')
    Set-Acl -LiteralPath $Path -AclObject $acl
}

$principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Run this installer elevated.' }
if (Get-Service -Name $name -ErrorAction SilentlyContinue) { throw "$name is already installed; run Uninstall-EndpointService.ps1 first." }
if (($EnrollmentOrigin -or $BootstrapFile) -and -not ($EnrollmentOrigin -and $BootstrapFile)) { throw 'Enrollment needs both -EnrollmentOrigin and -BootstrapFile.' }
# Only Program Files keeps ordinary users from replacing the service image.
$programFiles = [IO.Path]::GetFullPath($env:ProgramFiles).TrimEnd('\') + '\'
if (-not ($InstallDir + '\').StartsWith($programFiles, [StringComparison]::OrdinalIgnoreCase)) { throw "-InstallDir must be under $programFiles" }
foreach ($file in @($AgentPath, $CAFile, $BootstrapFile, $SamplingConfig) | Where-Object { $_ }) {
    if (-not (Test-Path -LiteralPath $file -PathType Leaf)) { throw "input file $file does not exist" }
}

$exe = Join-Path $InstallDir 'endpoint-agent.exe'
$config = Join-Path $Root 'service.json'
$registered = $false
$moved = $false
$bootstrapPath = $null
try {
    $null = New-Item -ItemType Directory -Force -Path $InstallDir
    Copy-Item -LiteralPath $AgentPath -Destination $exe -Force

    # The service SID only resolves once the service exists, so create it first.
    $binPath = "`"$exe`" --service --service-config `"$config`""
    $start = if ($StartType -eq 'Automatic') { 'auto' } else { 'demand' }
    Invoke-Native sc.exe @('create', $name, 'binPath=', $binPath, 'obj=', 'NT AUTHORITY\LocalService', 'start=', $start, 'DisplayName=', 'Device Audit endpoint collector')
    $registered = $true
    Invoke-Native sc.exe @('description', $name, 'Samples endpoint telemetry and signs it with the admitted device identity (TEL02 #26).')
    Invoke-Native sc.exe @('sidtype', $name, 'unrestricted')
    Invoke-Native sc.exe @('privs', $name, 'SeChangeNotifyPrivilege')
    $delay = $RestartDelaySeconds * 1000
    Invoke-Native sc.exe @('failure', $name, 'reset=', '86400', 'actions=', "restart/$delay/restart/$delay/restart/$delay")
    # Treat a non-zero service exit code as a failure, so recovery actions run.
    Invoke-Native sc.exe @('failureflag', $name, '1')
    $sid = ([Security.Principal.NTAccount]"NT SERVICE\$name").Translate([Security.Principal.SecurityIdentifier]).Value

    # Root: traverse, read and create-folder only, so the service can create
    # its private identity directory. 0x1200ad = generic read/execute + add subdirectory.
    $evidence = Join-Path $Root 'evidence'
    $enrollment = Join-Path $Root 'enrollment'
    $null = New-Item -ItemType Directory -Force -Path $Root, $evidence, $enrollment
    Set-PrivateAcl $Root "(A;;0x1200ad;;;$sid)"
    Set-PrivateAcl $evidence "(A;OICI;0x1301bf;;;$sid)"
    Set-PrivateAcl $enrollment "(A;OICI;0x1301bf;;;$sid)"
    foreach ($existing in Get-ChildItem -LiteralPath $evidence, $enrollment -File -Force) {
        Set-PrivateAcl $existing.FullName "(A;;0x1301bf;;;$sid)"
    }

    $enrollmentConfig = $null
    if ($EnrollmentOrigin) {
        $caPath = $null
        if ($CAFile) {
            $caPath = Join-Path $enrollment 'ca.pem'
            Copy-Item -LiteralPath $CAFile -Destination $caPath -Force
            Set-PrivateAcl $caPath "(A;;FR;;;$sid)"
        }
        $bootstrapPath = Join-Path $enrollment 'bootstrap.json'
        $enrollmentConfig = [ordered]@{ origin = $EnrollmentOrigin; ca_file = $caPath; bootstrap_file = $bootstrapPath }
    }
    $samplingPath = $null
    if ($SamplingConfig) {
        $samplingPath = Join-Path $Root 'sampling.json'
        Copy-Item -LiteralPath $SamplingConfig -Destination $samplingPath -Force
        Set-PrivateAcl $samplingPath "(A;;FR;;;$sid)"
    }
    [ordered]@{
        schema_version     = 'device-audit.endpoint-service.v1'
        state_dir          = (Join-Path $Root 'identity')
        evidence_dir       = $evidence
        max_evidence_bytes = $MaxEvidenceBytes
        max_evidence_records = $MaxEvidenceRecords
        sampling_config    = $samplingPath
        enrollment         = $enrollmentConfig
    } | ConvertTo-Json | Set-Content -LiteralPath $config -Encoding utf8NoBOM
    Set-PrivateAcl $config "(A;;FR;;;$sid)"
    # The credential moves last, so every earlier failure leaves it in place.
    if ($EnrollmentOrigin) {
        Move-Item -LiteralPath $BootstrapFile -Destination $bootstrapPath -Force
        $moved = $true
        # A moved file keeps its old DACL; replace it. Modify lets the service delete it.
        Set-PrivateAcl $bootstrapPath "(A;;0x1301bf;;;$sid)"
    }
} catch {
    # Roll back only this attempt: the credential returns to its original
    # path for a retry, and the registration is removed. State stays.
    if ($moved) {
        try { Move-Item -LiteralPath $bootstrapPath -Destination $BootstrapFile -Force } catch { Write-Warning "bootstrap file is still at ${bootstrapPath}: $_" }
    }
    if ($registered) {
        $out = & sc.exe delete $name 2>&1
        if ($LASTEXITCODE -ne 0) { Write-Warning "rollback could not delete $name; remove it with Uninstall-EndpointService.ps1: $out" }
    }
    throw
}
Write-Host "Installed $name ($StartType) as NT AUTHORITY\LocalService; config $config"
