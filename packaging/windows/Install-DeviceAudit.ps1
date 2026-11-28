#requires -Version 7.4
#requires -RunAsAdministrator
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$PackageDir,
    [Parameter(Mandatory)][ValidatePattern('\A[0-9a-f]{64}\z')][string]$SignerSHA256,
    [Parameter(Mandatory)][ValidatePattern('\A[0-9a-f]{40}\z')][string]$SourceCommit,
    [Parameter(Mandatory)][string]$EnrollmentOrigin,
    [Parameter(Mandatory)][string]$BootstrapFile,
    [string]$CAFile,
    [string]$SamplingConfig,
    [ValidatePattern('\A[0-9a-f]{64}\z')][string]$ModelPublisherSHA256,
    [string]$MeshServerKey,
    [string]$DERPRegionFile,
    [string]$ControllerAckKeyFile,
    [string]$DiagnosticControllerKeyFile,
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
$delivery = $MeshServerKey -or $DERPRegionFile -or $ControllerAckKeyFile -or $DiagnosticControllerKeyFile
if ($delivery -and -not ($MeshServerKey -and $DERPRegionFile -and $ControllerAckKeyFile)) {
    throw 'Mesh delivery requires -MeshServerKey, -DERPRegionFile and -ControllerAckKeyFile together.'
}

$name = 'DeviceAuditEndpoint'
$programFiles = [Environment]::GetFolderPath('ProgramFiles')
$stateParent = Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'DeviceAudit'
$root = Join-Path $stateParent 'Endpoint'
$installDir = Join-Path $programFiles 'DeviceAudit'
$stage = Join-Path $programFiles ("DeviceAudit-install-" + [guid]::NewGuid())
$sc = Join-Path ([Environment]::SystemDirectory) 'sc.exe'
$privateDacl = 'D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)'
$trustedAccounts = @('S-1-5-18', 'S-1-5-32-544', [Security.Principal.WindowsIdentity]::GetCurrent().User.Value)

. (Join-Path $PSScriptRoot 'Distribution.ps1')

$lock = [Threading.Mutex]::new($false, 'Global\DeviceAuditEndpointCleanInstall')
$locked = $false
$stageOwned = $false
$stateOwned = $false
$installOwned = $false
try {
    try { $locked = $lock.WaitOne(0) } catch [Threading.AbandonedMutexException] { $locked = $true }
    if (-not $locked) { throw 'Another clean install is in progress.' }
    if ((Get-Service -Name $name -ErrorAction SilentlyContinue) -or
        (Test-Path -LiteralPath $stateParent) -or (Test-Path -LiteralPath $installDir)) {
        throw 'Clean install requires the service, Program Files installation and ProgramData state to be absent.'
    }
    New-PrivateDirectory $stage
    $stageOwned = $true
    $release = Read-Distribution
    $credential = Join-Path $stage 'bootstrap.json'
    Copy-Input $BootstrapFile $credential 16KB -Secret
    $arguments = @{
        AgentPath = (Join-Path $stage 'endpoint-agent.exe')
        Root = $root
        InstallDir = $installDir
        StartType = 'Manual'
        DeferRecovery = $true
        EnrollmentOrigin = $EnrollmentOrigin
        BootstrapFile = $credential
    }
    foreach ($inputFile in @{ CAFile = $CAFile; SamplingConfig = $SamplingConfig }.GetEnumerator()) {
        if ($inputFile.Value) {
            $snapshot = Join-Path $stage $inputFile.Key
            Copy-Input $inputFile.Value $snapshot 256KB
            $arguments[$inputFile.Key] = $snapshot
        }
    }

    New-PrivateDirectory $stateParent
    $stateOwned = $true
    New-PrivateDirectory $installDir
    $installOwned = $true
    & (Join-Path $stage 'Install-EndpointService.ps1') @arguments | Out-Null
    $config = Join-Path $root 'service.json'
    $settings = Get-Content -LiteralPath $config -Raw | ConvertFrom-Json -AsHashtable
    $sid = ([Security.Principal.NTAccount]"NT SERVICE\$name").Translate([Security.Principal.SecurityIdentifier]).Value
    $parentAcl = Get-Acl -LiteralPath $stateParent
    $parentAcl.SetSecurityDescriptorSddlForm("$privateDacl(A;;0x1200a0;;;$sid)", 'Access')
    Set-Acl -LiteralPath $stateParent -AclObject $parentAcl
    $imageAcl = Get-Acl -LiteralPath $installDir
    $imageAcl.SetSecurityDescriptorSddlForm("$privateDacl(A;OICI;GRGX;;;$sid)", 'Access')
    Set-Acl -LiteralPath $installDir -AclObject $imageAcl
    if ($release.model_included) {
        $model = Join-Path $installDir 'model'
        Copy-Item -LiteralPath (Join-Path $stage 'model') -Destination $model -Recurse
        $evaluation = Join-Path $model 'evaluation.json'
        $settings['inference'] = @{
            manifest_file = (Join-Path $model 'manifest.json')
            artifact_file = (Join-Path $model 'artifact.json')
            publisher_key_file = (Join-Path $model 'publisher.pem')
            evaluation_file = $evaluation
            evaluation_sha256 = (Get-FileHash -LiteralPath $evaluation).Hash.ToLowerInvariant()
        }
    }
    if ($delivery) {
        $settings['delivery'] = @{ mesh_server_key = $MeshServerKey }
        $inputs = @{
            derp_region_file = $DERPRegionFile
            controller_ack_key_file = $ControllerAckKeyFile
            diagnostic_controller_key_file = $DiagnosticControllerKeyFile
        }
        foreach ($entry in $inputs.GetEnumerator()) {
            if ($entry.Value) {
                $path = Join-Path $installDir $entry.Key
                Copy-Input $entry.Value $path 64KB
                $settings.delivery[$entry.Key] = $path
            }
        }
    }
    $settings | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $config -Encoding utf8NoBOM
    $null = & (Join-Path $installDir 'endpoint-agent.exe') --check-service-config --service-config $config
    if ($LASTEXITCODE -ne 0) { throw 'The endpoint rejected its release configuration.' }

    try { Start-Service -Name $name } catch { throw 'The endpoint could not start under the service control manager.' }
    $log = Join-Path $root 'evidence/service.log'
    $deadline = [Diagnostics.Stopwatch]::StartNew()
    do {
        $service = Get-Service -Name $name
        if ($service.Status -ne 'Running') { throw 'The endpoint stopped before confirming collection.' }
        if ((Test-Path -LiteralPath $log) -and
            (Select-String -LiteralPath $log -SimpleMatch 'first endpoint telemetry snapshot signed and queued' -Quiet) -and
            -not (Test-Path -LiteralPath $settings.enrollment.bootstrap_file)) {
            break
        }
        if ($deadline.Elapsed.TotalSeconds -ge $StartupTimeoutSeconds) { throw 'First signed telemetry and bootstrap removal were not confirmed before timeout.' }
        Start-Sleep -Milliseconds 500
    } while ($true)

    foreach ($file in 'Uninstall-EndpointService.ps1', 'provenance.json', 'provenance.p7s') {
        Copy-Item -LiteralPath (Join-Path $stage $file) -Destination $installDir
    }
    Invoke-Sc @('failure', $name, 'reset=', '86400', 'actions=', 'restart/60000/restart/60000/restart/60000')
    Invoke-Sc @('failureflag', $name, '1')
    Set-Service -Name $name -StartupType Automatic
    if ((Get-Service -Name $name).Status -ne 'Running') { throw 'The endpoint stopped before install completed.' }
    Write-Host "Installed $name from $($release.source_commit) and confirmed the first signed telemetry snapshot."
} catch {
    if ($installOwned) {
        # Keep the registration disabled even if subsequent cleanup fails.
        try {
            if (Get-Service -Name $name -ErrorAction SilentlyContinue) { Set-Service -Name $name -StartupType Disabled }
            & (Join-Path $stage 'Uninstall-EndpointService.ps1') -Root $root -InstallDir $installDir -PurgeState
        } catch {
            Write-Warning 'Automatic rollback could not remove all service state. Follow the recovery instructions before retrying.'
        }
        # If stopping/removing the service failed, still delete the provisioned
        # credential independently. Its enclosing directory already has a private DACL.
        $secret = Join-Path $root 'enrollment/bootstrap.json'
        if (Test-Path -LiteralPath $secret) {
            try { Remove-Item -LiteralPath $secret -Force } catch { Write-Warning 'Remove the private provisioned bootstrap file during recovery.' }
        }
        if (-not (Get-Service -Name $name -ErrorAction SilentlyContinue)) { Remove-Item -LiteralPath $installDir -Recurse -Force }
    }
    if ($stateOwned -and -not (Test-Path -LiteralPath $root)) { Remove-Item -LiteralPath $stateParent -Force }
    throw
} finally {
    try {
        if ($stageOwned) {
            try { Remove-Item -LiteralPath $stage -Recurse -Force } catch {
                Write-Warning "Could not remove private staging directory $stage. Remove it from an elevated session."
            }
        }
    } finally {
        if ($locked) { $lock.ReleaseMutex() }
        $lock.Dispose()
    }
}
