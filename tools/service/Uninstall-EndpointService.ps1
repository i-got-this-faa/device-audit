#requires -Version 7.3
<#
.SYNOPSIS
Stops and removes the DeviceAuditEndpoint service (TEL02 #26).

.DESCRIPTION
Keeps <Root>, including the admitted identity and signed evidence, unless
-PurgeState is given. Purging deletes the identity keys; a later install must
enroll again with a new bootstrap credential. Purge refuses a directory that
holds anything but the endpoint's own entries (a partial install is fine), so a mistyped -Root cannot
delete unrelated files.
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
$owned = 'service.json', 'sampling.json', 'evidence', 'enrollment', 'identity'
if ($PurgeState -and (Test-Path -LiteralPath $Root)) {
    $foreign = @(Get-ChildItem -LiteralPath $Root -Force -Name | Where-Object { $_ -notin $owned })
    # A partial install may lack service.json; only foreign entries block the purge.
    if ($foreign.Count -gt 0) {
        throw "refusing to purge ${Root}: it is not a dedicated endpoint state directory"
    }
}
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
    # Add Administrators instead of resetting: /reset would restore inherited
    # access from the parent and expose evidence if the delete then failed.
    $out = & icacls.exe $Root /grant:r "*S-1-5-32-544:(OI)(CI)F" /T /C /Q 2>&1
    if ($LASTEXITCODE -ne 0) { throw "icacls grant failed ($LASTEXITCODE): $out" }
    Remove-Item -LiteralPath $Root -Recurse -Force
}
Write-Host "Removed $name$(if ($PurgeState) { ' and purged its state' } else { '; state kept' })"
