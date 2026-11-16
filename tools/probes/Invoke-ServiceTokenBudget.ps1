#requires -Version 7.0
# Install two disposable services on a GitHub-hosted Windows runner and measure
# 15s and 60s cadences under those tokens. This refuses to run outside that
# runner so it cannot modify a physical machine.
[CmdletBinding()]
param([int]$Samples = 30)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
if ($env:GITHUB_ACTIONS -ne 'true') { throw 'This service installation runs only on a GitHub-hosted runner.' }
if ($Samples -lt 1 -or $Samples -gt 30) { throw 'Samples must be from 1 to 30.' }
$repo = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
$root = Join-Path $repo 'artifacts\service-budget'
$pwsh = (Get-Command pwsh).Source
if ([IO.Path]::GetFileName($pwsh) -ne 'pwsh.exe') { throw 'pwsh.exe was not found.' }

function Grant-MeasurementAccess {
    param([string]$Path, [string[]]$Identities, [string]$Rights)
    foreach ($identity in $Identities) {
        & icacls.exe $Path /grant "${identity}:${Rights}" /T /C | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "icacls failed for $identity on $Path" }
    }
}

function Install-MeasurementService {
    param([string]$Name, [string]$Binary, [string]$Config, [string]$Account, [string]$Password)
    $bin = "$Binary --service $Name --config $Config"
    $create = "sc.exe create $Name binPath= `"$bin`" start= demand obj= `"$Account`" password= `"$Password`""
    $created = & cmd.exe /d /c $create 2>&1 | Out-String
    if ($LASTEXITCODE -ne 0) { throw "sc create $Name failed with exit code ${LASTEXITCODE}: $created" }
    $sidType = & cmd.exe /d /c "sc.exe sidtype $Name unrestricted" 2>&1 | Out-String
    if ($LASTEXITCODE -ne 0) { throw "sc sidtype $Name failed with exit code ${LASTEXITCODE}: $sidType" }
}

function Remove-MeasurementService {
    param([string]$Name)
    & cmd.exe /d /c "sc.exe stop $Name" | Out-Null
    & cmd.exe /d /c "sc.exe delete $Name" | Out-Null
}

function Wait-MeasurementService {
    param([string]$Name, [string]$OutputDir)
    $deadline = (Get-Date).AddHours(3)
    do {
        Start-Sleep -Seconds 20
        $service = Get-Service -Name $Name
        $log = Join-Path $OutputDir 'service.log'
        $last = ''
        if (Test-Path -LiteralPath $log) { $last = (Get-Content -LiteralPath $log -Tail 1 -ErrorAction SilentlyContinue) }
        Write-Host "$Name $($service.Status) $last"
    } while ($service.Status -ne 'Stopped' -and (Get-Date) -lt $deadline)
    if ($service.Status -ne 'Stopped') { throw "$Name did not stop before the wait limit" }
    $statusPath = Join-Path $OutputDir 'status.json'
    if (-not (Test-Path -LiteralPath $statusPath)) { throw "$Name wrote no status.json" }
    $status = Get-Content -LiteralPath $statusPath -Raw | ConvertFrom-Json
    if (-not $status.ok) { throw "$Name failed: $($status.error)" }
}

function Assert-TokenAttestation {
    param([string]$Path, [string]$ExpectedRole)
    $token = Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json
    if ($token.host_role -ne 'github_hosted_windows_runner_not_physical_target') {
        throw "$ExpectedRole attestation has the wrong host role"
    }
    if ($token.administrators_group -or $token.elevated) {
        throw "$ExpectedRole token is elevated or in Administrators"
    }
    $broad = @('SeDebugPrivilege', 'SeTcbPrivilege', 'SeBackupPrivilege', 'SeSecurityPrivilege', 'SeTakeOwnershipPrivilege')
    foreach ($privilege in @($token.privileges)) {
        if ($privilege.enabled -and $broad -contains $privilege.name) {
            throw "$ExpectedRole token has enabled $($privilege.name)"
        }
    }
    foreach ($group in @($token.groups)) {
        if ($group.enabled -and $group.sid -in @('S-1-5-32-544', 'S-1-5-32-573', 'S-1-5-32-559')) {
            throw "$ExpectedRole token has enabled group $($group.sid)"
        }
    }
    if (-not $token.service_sid_present -or [string]::IsNullOrEmpty($token.service_sid)) {
        throw "$ExpectedRole token has no per-service SID"
    }
    if ($ExpectedRole -eq 'local_service' -and $token.account_sid -ne 'S-1-5-19') {
        throw "local service account SID is $($token.account_sid)"
    }
    if ($ExpectedRole -eq 'denied' -and $token.account_sid -in @('S-1-5-18', 'S-1-5-19')) {
        throw "denied token is a built-in service account"
    }
    if ([string]::IsNullOrWhiteSpace($token.whoami_all)) { throw "$ExpectedRole is missing whoami /all" }
}

function Grant-ServiceLogonRight {
    param([string]$AccountName)
    # This is the logon right a service account needs. It is not an administrator
    # membership and it does not change sensor, WMI or event-log ACLs.
    $sid = (Get-LocalUser -Name $AccountName).Sid.Value
    $cfg = Join-Path $env:RUNNER_TEMP 'service-logon.cfg'
    $db = Join-Path $env:RUNNER_TEMP 'service-logon.sdb'
    & secedit.exe /export /cfg $cfg /areas USER_RIGHTS | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'secedit could not export user rights' }
    $text = Get-Content -LiteralPath $cfg -Raw
    $text = [regex]::Replace($text, '(?m)^SeServiceLogonRight\s*=\s*(.*)$', {
        param($match)
        $current = $match.Groups[1].Value
        if ($current -like "*$sid*") { return $match.Value }
        return "SeServiceLogonRight = $current,*$sid"
    })
    if ($text -notlike "*$sid*") { throw 'SeServiceLogonRight was not updated' }
    Set-Content -LiteralPath $cfg -Value $text -Encoding unicode
    & secedit.exe /configure /db $db /cfg $cfg /areas USER_RIGHTS | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'secedit could not grant Log on as a service' }
}

function Start-TokenMeasurement {
    param([string]$Name, [string]$Role, [string]$Account, [string]$Password, [string[]]$Readers)
    $dir = Join-Path $root $Role
    New-Item -ItemType Directory -Force -Path $dir | Out-Null
    $config = Join-Path $dir 'config.json'
    @{
        role = $(if ($Role -eq 'local') { 'local_service' } else { 'denied' })
        repo_root = $repo
        output_dir = $dir
        pwsh = $pwsh
        samples = $Samples
        iterations = 200000
        baseline = '2s'
        host_role = 'github_hosted_windows_runner_not_physical_target'
        service = $Name
    } | ConvertTo-Json | Set-Content -LiteralPath $config -Encoding utf8
    Grant-MeasurementAccess -Path $repo -Identities $Readers -Rights '(OI)(CI)RX'
    Grant-MeasurementAccess -Path $dir -Identities ($Readers + @("NT SERVICE\$Name")) -Rights '(OI)(CI)M'
    Install-MeasurementService -Name $Name -Binary (Join-Path $repo 'bin\collectorservice.exe') -Config $config -Account $Account -Password $Password
    & cmd.exe /d /c "sc.exe qc $Name" | Set-Content -LiteralPath (Join-Path $dir 'service-config.txt') -Encoding utf8
    Start-Service -Name $Name
    Wait-MeasurementService -Name $Name -OutputDir $dir
    Assert-TokenAttestation -Path (Join-Path $dir 'attestation.json') -ExpectedRole $(if ($Role -eq 'local') { 'local_service' } else { 'denied' })
}

if (-not (Test-Path -LiteralPath (Join-Path $repo 'bin'))) { New-Item -ItemType Directory -Path (Join-Path $repo 'bin') | Out-Null }
$env:CGO_ENABLED = '0'
& go build -o (Join-Path $repo 'bin\collectorservice.exe') ./tools/probes/collectorservice
if ($LASTEXITCODE -ne 0) { throw 'collectorservice build failed' }
& go build -o (Join-Path $repo 'bin\collectorbudget.exe') ./tools/probes/collectorbudget
if ($LASTEXITCODE -ne 0) { throw 'collectorbudget build failed' }

$deniedPassword = 'Aa1x' + ((1..24 | ForEach-Object { '{0:x2}' -f (Get-Random -Maximum 256) }) -join '')
Write-Host "::add-mask::$deniedPassword"
$failures = @()
try {
    Import-Module Microsoft.PowerShell.LocalAccounts
    if (Get-LocalUser -Name 'deviceaudit-denied' -ErrorAction SilentlyContinue) {
        Remove-LocalUser -Name 'deviceaudit-denied'
    }
    $secure = ConvertTo-SecureString $deniedPassword -AsPlainText -Force
    New-LocalUser -Name 'deviceaudit-denied' -Password $secure -PasswordNeverExpires -UserMayNotChangePassword -AccountNeverExpires | Out-Null
    $member = Get-LocalGroupMember -Group 'Administrators' -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -like '*\deviceaudit-denied' }
    if ($member) { throw 'The denied account is in Administrators.' }
    foreach ($group in 'Event Log Readers', 'Performance Log Users') {
        $extra = Get-LocalGroupMember -Group $group -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -like '*\deviceaudit-denied' }
        if ($extra) { throw "The denied account is in $group." }
    }
    Grant-ServiceLogonRight -AccountName 'deviceaudit-denied'
    Grant-MeasurementAccess -Path (Split-Path -Parent $pwsh) -Identities @('NT AUTHORITY\LOCAL SERVICE', 'deviceaudit-denied') -Rights '(OI)(CI)RX'
    try {
        Start-TokenMeasurement -Name 'DeviceAuditLocal' -Role 'local' -Account 'NT AUTHORITY\LocalService' -Password '' -Readers @('NT AUTHORITY\LOCAL SERVICE')
    } catch {
        $failures += $_.Exception.Message
        Write-Host "LOCAL SERVICE MEASUREMENT FAILED: $($_.Exception.Message)"
    }
    try {
        Start-TokenMeasurement -Name 'DeviceAuditDenied' -Role 'denied' -Account '.\deviceaudit-denied' -Password $deniedPassword -Readers @('deviceaudit-denied')
    } catch {
        $failures += $_.Exception.Message
        Write-Host "DENIED TOKEN MEASUREMENT FAILED: $($_.Exception.Message)"
    }
} finally {
    Remove-MeasurementService 'DeviceAuditLocal'
    Remove-MeasurementService 'DeviceAuditDenied'
    if (Get-LocalUser -Name 'deviceaudit-denied' -ErrorAction SilentlyContinue) {
        Remove-LocalUser -Name 'deviceaudit-denied'
    }
}
if ($failures.Count -gt 0) { throw ($failures -join [Environment]::NewLine) }
Write-Host 'PASS: hosted-runner LocalService and denied-token measurements'
