#requires -Version 7.4
#requires -RunAsAdministrator
[CmdletBinding(DefaultParameterSetName = 'Update')]
param(
    [Parameter(Mandatory, ParameterSetName = 'Update')][string]$PackageDir,
    [Parameter(Mandatory, ParameterSetName = 'Update')][ValidatePattern('\A[0-9a-f]{64}\z')][string]$SignerSHA256,
    [Parameter(Mandatory, ParameterSetName = 'Update')][ValidatePattern('\A[0-9a-f]{40}\z')][string]$SourceCommit,
    [Parameter(ParameterSetName = 'Update')][ValidatePattern('\A[0-9a-f]{64}\z')][string]$ModelPublisherSHA256,
    [Parameter(Mandatory, ParameterSetName = 'Recover')][switch]$Recover,
    [ValidateRange(15, 600)][int]$StartupTimeoutSeconds = 180
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $false
if (-not $IsWindows -or [Runtime.InteropServices.RuntimeInformation]::OSArchitecture -ne 'X64' -or
    [Runtime.InteropServices.RuntimeInformation]::ProcessArchitecture -ne 'X64' -or
    [Environment]::OSVersion.Version.Build -lt 26100) {
    throw 'Use x64 PowerShell 7.4+ on Windows build 26100 or later. See the release support matrix.'
}

$name = 'DeviceAuditEndpoint'
$programFiles = [Environment]::GetFolderPath('ProgramFiles')
$stateParent = Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'DeviceAudit'
$root = Join-Path $stateParent 'Endpoint'
$installDir = Join-Path $programFiles 'DeviceAudit'
$stage = Join-Path $programFiles ("DeviceAudit-install-" + [guid]::NewGuid())
$config = Join-Path $root 'service.json'
$version = Join-Path $root 'endpoint-state.version'
$journal = Join-Path $installDir 'upgrade-pending.json'
$serviceKey = "SYSTEM\CurrentControlSet\Services\$name"
$sc = Join-Path ([Environment]::SystemDirectory) 'sc.exe'
$privateDacl = 'D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)'
$trustedAccounts = @('S-1-5-18', 'S-1-5-32-544', [Security.Principal.WindowsIdentity]::GetCurrent().User.Value)
. (Join-Path $PSScriptRoot 'Distribution.ps1')

# Publish only flushed files. Flush the SCM registry key before deleting the
# recovery record so the final ImagePath and Automatic startup survive reboot.
if (-not ('DeviceAudit.UpgradeNative' -as [type])) {
    Add-Type -TypeDefinition @'
using System.Runtime.InteropServices;
namespace DeviceAudit {
    public static class UpgradeNative {
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern bool MoveFileEx(string source, string destination, int flags);
        [DllImport("advapi32.dll")]
        public static extern int RegFlushKey(Microsoft.Win32.SafeHandles.SafeRegistryHandle key);
    }
}
'@
}

function Get-RegularItem([string]$Path, [bool]$Directory = $false) {
    $item = Get-Item -LiteralPath $Path -Force
    if ($Directory -ne $item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw "Expected an ordinary installed path at $Path."
    }
    return $item
}

function Publish-Text([string]$Path, [string]$Text, [string]$ServiceAce = '') {
    $temporary = "$Path.tmp"
    if (Test-Path -LiteralPath $temporary) {
        $null = Get-RegularItem $temporary
        Remove-Item -LiteralPath $temporary -Force
    }
    $file = [IO.File]::Open($temporary, 'CreateNew', 'Write', 'None')
    try {
        $bytes = [Text.Encoding]::UTF8.GetBytes($Text)
        $file.Write($bytes, 0, $bytes.Length)
        $file.Flush($true)
    } finally { $file.Dispose() }
    $acl = Get-Acl -LiteralPath $temporary
    $acl.SetSecurityDescriptorSddlForm("D:P(A;;FA;;;SY)(A;;FA;;;BA)$ServiceAce", 'Access')
    Set-Acl -LiteralPath $temporary -AclObject $acl
    # MOVEFILE_WRITE_THROUGH. No replacement of a committed file is allowed.
    if (-not [DeviceAudit.UpgradeNative]::MoveFileEx($temporary, $Path, 8)) {
        throw "Could not commit $Path."
    }
    $file = [IO.File]::Open($Path, 'Open', 'ReadWrite', 'Read')
    try { $file.Flush($true) } finally { $file.Dispose() }
}

function Get-Registration {
    $key = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($serviceKey)
    if ($null -eq $key) { throw 'The endpoint service is missing.' }
    try {
        return @{
            Image = $key.GetValue('ImagePath', $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
            Start = $key.GetValue('Start')
        }
    } finally { $key.Dispose() }
}

function Flush-Registration {
    $key = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($serviceKey)
    try {
        if ([DeviceAudit.UpgradeNative]::RegFlushKey($key.Handle) -ne 0) { throw 'Could not flush endpoint registration.' }
    } finally { $key.Dispose() }
}

function Get-ImageDir([string]$Slot) {
    if ($Slot -ceq 'original') { return $installDir }
    if ($Slot -cnotmatch '\A[0-9a-f]{32}\z') { throw 'Invalid endpoint release slot.' }
    return (Join-Path $installDir "release-$Slot")
}

function Get-ImageCommand([string]$Slot) {
    $exe = Join-Path (Get-ImageDir $Slot) 'endpoint-agent.exe'
    return ('"{0}" --service --service-config "{1}"' -f $exe, $config)
}

function Get-ActiveSlot([string]$Image) {
    if ($Image -ieq (Get-ImageCommand 'original')) { return 'original' }
    if ($Image -match '\\release-([0-9a-f]{32})\\endpoint-agent\.exe"') {
        $slot = $Matches[1].ToLowerInvariant()
        if ($Image -ieq (Get-ImageCommand $slot)) { return $slot }
    }
    throw 'The SCM image is outside the supported Windows package layout.'
}

function Stop-Endpoint {
    Set-Service -Name $name -StartupType Disabled
    $service = Get-Service -Name $name
    if ($service.Status -ne 'Stopped' -and $service.Status -ne 'StopPending') { $service.Stop() }
    $service.WaitForStatus('Stopped', [TimeSpan]::FromSeconds($StartupTimeoutSeconds))
}

function Restore-Endpoint {
    $null = Get-RegularItem $journal
    $transaction = Get-Content -LiteralPath $journal -Raw | ConvertFrom-Json -AsHashtable
    if ($transaction.schema -cne 'device-audit.windows-upgrade.v1' -or
        $transaction.candidate -cnotmatch '\A[0-9a-f]{32}\z' -or $transaction.prior -ceq $transaction.candidate) {
        throw 'Invalid upgrade recovery record.'
    }
    $prior = Get-ImageCommand $transaction.prior
    $candidate = Get-ImageCommand $transaction.candidate
    if ((Get-Registration).Image -inotIn @($prior, $candidate, "$candidate --upgrade-readiness-token $($transaction.candidate)")) {
        throw 'Service registration changed outside the pending upgrade.'
    }
    $null = Get-RegularItem (Get-ImageDir $transaction.prior) $true
    $null = Get-RegularItem (Join-Path (Get-ImageDir $transaction.prior) 'endpoint-agent.exe')
    Stop-Endpoint
    Invoke-Sc @('config', $name, 'binPath=', $prior, 'start=', 'auto')
    Flush-Registration
    Start-Service -Name $name
    if ((Get-Service -Name $name).Status -ne 'Running') { throw 'The prior service image could not start.' }
    Remove-Item -LiteralPath $journal -Force
    try {
        $discard = Get-ImageDir $transaction.candidate
        if (Test-Path -LiteralPath $discard) {
            $null = Get-RegularItem $discard $true
            Remove-Item -LiteralPath $discard -Recurse -Force
        }
    } catch { Write-Warning 'Could not remove the unused candidate from Program Files.' }
    Write-Host 'Restored the prior service image. The service uses the live endpoint state.'
}

function Assert-CompatibleInstall([string]$Slot) {
    $dir = Get-ImageDir $Slot
    $null = Get-RegularItem $dir $true
    $null = Get-RegularItem (Join-Path $dir 'endpoint-agent.exe')
    $null = Get-RegularItem (Join-Path $dir 'provenance.p7s')
    $installed = Get-RegularItem (Join-Path $dir 'provenance.json')
    $release = Get-Content -LiteralPath $installed.FullName -Raw | ConvertFrom-Json -AsHashtable
    if ($release.schema_version -cne 'device-audit.windows-release.v1' -or
        $release.source_repository -cne 'https://github.com/i-got-this-faa/device-audit' -or
        $release.source_commit -cnotmatch '\A[0-9a-f]{40}\z' -or $release.target -cne 'windows/amd64' -or
        ($release.Contains('endpoint_state_version') -and $release.endpoint_state_version -cne 1)) {
        throw 'The installed release is outside the supported endpoint layout.'
    }
    if ($release.source_commit -ieq $SourceCommit) { throw 'This source commit is already installed.' }

    $null = Get-RegularItem $stateParent $true
    $null = Get-RegularItem $root $true
    $null = Get-RegularItem $config
    $settings = Get-Content -LiteralPath $config -Raw | ConvertFrom-Json -AsHashtable
    if ($settings.schema_version -cne 'device-audit.endpoint-service.v1' -or
        $settings.state_dir -ine (Join-Path $root 'identity') -or $settings.evidence_dir -ine (Join-Path $root 'evidence') -or
        ($settings.enrollment -and (Test-Path -LiteralPath $settings.enrollment.bootstrap_file))) {
        throw 'The upgrade requires the standard package configuration and completed enrollment.'
    }
    $null = Get-RegularItem $settings.evidence_dir $true
}

$lock = [Threading.Mutex]::new($false, 'Global\DeviceAuditEndpointCleanInstall')
$locked = $false
$stageOwned = $false
$unpublishedCandidate = $null
try {
    try { $locked = $lock.WaitOne(0) } catch [Threading.AbandonedMutexException] { $locked = $true }
    if (-not $locked) { throw 'Another endpoint installation or upgrade is in progress.' }
    $null = Get-RegularItem $installDir $true
    if (Test-Path -LiteralPath $journal) {
        if (-not $Recover) { throw 'An upgrade was interrupted. Run this script with -Recover before retrying.' }
        Restore-Endpoint
        return
    }
    if ($Recover) { throw 'There is no pending endpoint upgrade.' }

    $registration = Get-Registration
    if ($registration.Start -ne 2) { throw 'The installed endpoint must be configured for Automatic startup.' }
    $prior = Get-ActiveSlot $registration.Image
    Assert-CompatibleInstall $prior
    New-PrivateDirectory $stage
    $stageOwned = $true
    $release = Read-Distribution
    if (-not $release.Contains('endpoint_state_version') -or
        ($release.endpoint_state_version -isnot [long] -and $release.endpoint_state_version -isnot [int]) -or
        $release.endpoint_state_version -ne 1) {
        throw 'The signed release does not declare compatible endpoint state version 1.'
    }

    $exe = Join-Path $stage 'endpoint-agent.exe'
    $null = & $exe --check-service-config --service-config $config
    if ($LASTEXITCODE -ne 0) { throw 'The candidate rejected the installed configuration or state version.' }
    if (Test-Path -LiteralPath $version) {
        $null = Get-RegularItem $version
        if ([IO.File]::ReadAllText($version) -cne "1`n") { throw 'The installed endpoint state version is incompatible.' }
    }

    $candidate = [guid]::NewGuid().ToString('N')
    $candidateDir = Get-ImageDir $candidate
    $null = New-Item -ItemType Directory -Path $candidateDir
    $unpublishedCandidate = $candidateDir
    foreach ($file in 'endpoint-agent.exe', 'provenance.json', 'provenance.p7s') {
        $destination = Join-Path $candidateDir $file
        Copy-Item -LiteralPath (Join-Path $stage $file) -Destination $destination
        $fileHandle = [IO.File]::Open($destination, 'Open', 'ReadWrite', 'Read')
        try { $fileHandle.Flush($true) } finally { $fileHandle.Dispose() }
    }
    Remove-Item -LiteralPath $stage -Recurse -Force
    $stageOwned = $false

    $transaction = @{ schema = 'device-audit.windows-upgrade.v1'; prior = $prior; candidate = $candidate }
    Publish-Text $journal ($transaction | ConvertTo-Json -Compress)
    $unpublishedCandidate = $null
    try {
        Stop-Endpoint
        if (-not (Test-Path -LiteralPath $version)) {
            # Adopt the unmarked PKG01 layout as v1 without editing service-owned files.
            $sid = ([Security.Principal.NTAccount]"NT SERVICE\$name").Translate([Security.Principal.SecurityIdentifier]).Value
            Publish-Text $version "1`n" "(A;;FR;;;$sid)"
        }
        $command = Get-ImageCommand $candidate
        Invoke-Sc @('config', $name, 'binPath=', "$command --upgrade-readiness-token $candidate", 'start=', 'demand')
        Start-Service -Name $name
        $log = Join-Path $root 'evidence\service.log'
        $deadline = [Diagnostics.Stopwatch]::StartNew()
        do {
            if ((Get-Service -Name $name).Status -ne 'Running') { throw 'The candidate stopped during the upgrade trial. See service.log.' }
            if ((Test-Path -LiteralPath $log) -and
                (Select-String -LiteralPath $log -SimpleMatch "endpoint upgrade ready $candidate" -Quiet)) { break }
            if ($deadline.Elapsed.TotalSeconds -ge $StartupTimeoutSeconds) { throw 'The candidate did not report readiness. See service.log.' }
            Start-Sleep -Milliseconds 250
        } while ($true)

        Invoke-Sc @('config', $name, 'binPath=', $command, 'start=', 'auto')
        Flush-Registration
        if ((Get-Service -Name $name).Status -ne 'Running') { throw 'The candidate stopped before upgrade commit.' }
        Remove-Item -LiteralPath $journal -Force
    } catch {
        try { Restore-Endpoint } catch {
            Write-Warning "Automatic recovery is incomplete. Run this script with -Recover. $($_.Exception.Message)"
        }
        throw
    }
    Write-Host "Upgraded $name to $($release.source_commit) using endpoint state version 1."
} finally {
    try {
        if ($stageOwned) { Remove-Item -LiteralPath $stage -Recurse -Force }
        if ($unpublishedCandidate -and -not (Test-Path -LiteralPath $journal)) {
            Remove-Item -LiteralPath $unpublishedCandidate -Recurse -Force
        }
    } finally {
        if ($locked) { $lock.ReleaseMutex() }
        $lock.Dispose()
    }
}
