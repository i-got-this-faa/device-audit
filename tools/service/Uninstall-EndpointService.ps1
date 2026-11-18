#requires -Version 7.0
<#
.SYNOPSIS
Stops and removes the DeviceAuditEndpoint service (TEL02 #26).

.DESCRIPTION
Keeps <Root>, including the admitted identity and signed evidence, unless
-PurgeState is given. Purging deletes the identity keys; a later install must
enroll again with a new bootstrap credential.
#>
[CmdletBinding()]
param(
    [string]$Root = (Join-Path $env:ProgramData 'DeviceAudit\Endpoint'),
    [string]$InstallDir = (Join-Path $env:ProgramFiles 'DeviceAudit'),
    [switch]$PurgeState
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$name = 'DeviceAuditEndpoint'
$service = Get-Service -Name $name -ErrorAction SilentlyContinue
if ($service) {
    if ($service.Status -ne 'Stopped') { Stop-Service -Name $name -Force }
    $out = & sc.exe delete $name 2>&1
    if ($LASTEXITCODE -ne 0) { throw "sc.exe delete failed ($LASTEXITCODE): $out" }
}
$exe = Join-Path $InstallDir 'endpoint-agent.exe'
if (Test-Path -LiteralPath $exe) { Remove-Item -LiteralPath $exe -Force }
if ($PurgeState -and (Test-Path -LiteralPath $Root)) {
    # The identity directory grants only SYSTEM and the service SID; take
    # ownership so an administrator can remove it.
    $out = & takeown.exe /F $Root /R /A /D Y 2>&1
    if ($LASTEXITCODE -ne 0) { throw "takeown failed ($LASTEXITCODE): $out" }
    $out = & icacls.exe $Root /reset /T /C /Q 2>&1
    if ($LASTEXITCODE -ne 0) { throw "icacls reset failed ($LASTEXITCODE): $out" }
    Remove-Item -LiteralPath $Root -Recurse -Force
}
Write-Host "Removed $name$(if ($PurgeState) { ' and purged its state' } else { '; state kept' })"
