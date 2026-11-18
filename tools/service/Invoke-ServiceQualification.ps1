#requires -Version 7.3
<#
.SYNOPSIS
Qualifies the DeviceAuditEndpoint service on this machine (TEL02 #26).

.DESCRIPTION
Run elevated while TestServiceQualificationHarness is waiting (see
docs/validation/windows-service-26.md). It refuses to start when the service
or its state directory already exists, so cleanup only removes what this run
created. It installs the service with the harness's bootstrap file, then:

  1. checks that an interactive --service run is refused;
  2. starts the service, which enrolls and samples, and stops it cleanly;
  3. starts it again on the same identity;
  4. kills the process, waits for the SCM recovery restart, and requires a new
     signed envelope from the replacement process;
  5. lowers the spool record limit and verifies retention at capacity;
  6. checks that LocalSystem and an extra privilege are refused;
  7. copies the evidence, service log and identity ACL to <HarnessDir>\evidence,
     uninstalls the service and purges its test identity.

It writes <HarnessDir>\evidence\qualification.json and qualification-done,
which releases the harness to verify the signatures, and exits 1 if any step
failed.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$AgentPath,
    [Parameter(Mandatory)][string]$HarnessDir,
    # Bounded so the whole run fits inside the harness's 45-minute wait.
    [ValidateRange(30, 600)][int]$RunSeconds = 90
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$name = 'DeviceAuditEndpoint'
$root = Join-Path $env:ProgramData 'DeviceAudit\Endpoint'
$evidenceDir = Join-Path $root 'evidence'
$serviceLog = Join-Path $root 'evidence\service.log'
$out = Join-Path $HarnessDir 'evidence'
$steps = [Collections.Generic.List[object]]::new()

$principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Run this script elevated.' }
foreach ($file in 'bootstrap.json', 'ca.pem', 'origin.txt') {
    if (-not (Test-Path -LiteralPath (Join-Path $HarnessDir $file))) { throw "harness file $file is missing; start TestServiceQualificationHarness first" }
}
# Never touch an installation this run did not create.
if (Get-Service -Name $name -ErrorAction SilentlyContinue) { throw "$name already exists; qualify on a machine without it" }
if (Test-Path -LiteralPath $root) { throw "$root already exists; qualification needs a fresh state directory" }
$null = New-Item -ItemType Directory -Force -Path $out
$log = Join-Path $out 'qualification.log'

function Write-Step([string]$Message) {
    "$([DateTime]::UtcNow.ToString('o')) $Message" | Add-Content -LiteralPath $log
    Write-Host $Message
}
function Get-State {
    $s = Get-CimInstance Win32_Service -Filter "Name='$name'"
    [pscustomobject]@{ State = $s.State; ProcessId = $s.ProcessId; ExitCode = $s.ExitCode; ServiceExitCode = $s.ServiceSpecificExitCode }
}
function Wait-State([string]$State, [int]$Seconds) {
    $deadline = [DateTime]::UtcNow.AddSeconds($Seconds)
    while ([DateTime]::UtcNow -lt $deadline) {
        $s = Get-State
        if ($s.State -eq $State) { return $s }
        Start-Sleep -Milliseconds 500
    }
    throw "service did not reach $State within $Seconds s; last $(Get-State | ConvertTo-Json -Compress)"
}
function Add-Result([string]$Step, [bool]$Passed, $Detail) {
    $steps.Add([ordered]@{ step = $Step; passed = $Passed; detail = $Detail })
    Write-Step "$(if ($Passed) { 'PASS' } else { 'FAIL' }) $Step $($Detail | ConvertTo-Json -Compress -Depth 4)"
}
function Invoke-Sc([string[]]$Arguments) {
    $text = & sc.exe @Arguments 2>&1
    if ($LASTEXITCODE -ne 0) { throw "sc.exe $($Arguments -join ' ') failed ($LASTEXITCODE): $text" }
    ($text | Out-String).Trim()
}
function Get-EnvelopeCount {
    @(Get-ChildItem -LiteralPath $evidenceDir -Filter 'spool-*.json' -File).Count
}
function Start-AndExpectRefusal([string]$Step, [int]$ExitCode, [string]$Text) {
    $started = $true
    try { Start-Service -Name $name -ErrorAction Stop } catch { $started = $false }
    $s = Wait-State 'Stopped' 30
    $logText = Get-Content -LiteralPath $serviceLog -Raw
    Add-Result $Step ($s.ExitCode -eq 1066 -and $s.ServiceExitCode -eq $ExitCode -and $logText.Contains($Text)) @{ start_call_succeeded = $started; win32_exit_code = $s.ExitCode; service_exit_code = $s.ServiceExitCode; log_contains = $Text }
}

Write-Step "qualification started on Windows $([Environment]::OSVersion.Version)"
try {
    # 1. Interactive refusal, before anything is installed.
    # Exit code 1 is the expected result; keep it from becoming a script error.
    $PSNativeCommandUseErrorActionPreference = $false
    $text = & $AgentPath --service --service-config (Join-Path $root 'service.json') 2>&1
    Add-Result 'interactive_service_refused' ($LASTEXITCODE -eq 1 -and "$text".Contains('service control manager')) @{ exit_code = $LASTEXITCODE; stderr = "$text" }

    # Short cadence so a few minutes cover several snapshots per phase.
    $sampling = Join-Path $HarnessDir 'sampling.json'
    $sources = foreach ($source in 'cpu', 'memory', 'disk', 'network', 'battery', 'thermal', 'gpu_engine', 'gpu_vendor') {
        [ordered]@{ source = $source; interval = $(if ($source -eq 'gpu_vendor') { '30s' } else { '10s' }); deadline = '5s' }
    }
    [ordered]@{ schema_version = 'device-audit.sampling-config.v1'; emit_interval = '10s'
        budget = [ordered]@{ max_cpu_percent_one_core = 2; max_rss_bytes = 67108864 }; sources = @($sources)
    } | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $sampling -Encoding utf8NoBOM

    & "$PSScriptRoot/Install-EndpointService.ps1" -AgentPath $AgentPath -Root $root -StartType Manual -RestartDelaySeconds 5 -MaxEvidenceBytes 1MB `
        -EnrollmentOrigin (Get-Content -LiteralPath (Join-Path $HarnessDir 'origin.txt') -Raw).Trim() `
        -CAFile (Join-Path $HarnessDir 'ca.pem') -BootstrapFile (Join-Path $HarnessDir 'bootstrap.json') -SamplingConfig $sampling
    $config = [ordered]@{}
    foreach ($q in 'qc', 'qsidtype', 'qprivs', 'qfailure', 'qfailureflag') { $config[$q] = Invoke-Sc @($q, $name) }
    $config | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $out 'service-config.json') -Encoding utf8NoBOM

    # 2. First start: enroll, sample, stop cleanly.
    Start-Service -Name $name
    $first = Wait-State 'Running' 30
    Start-Sleep -Seconds $RunSeconds
    $bootstrapGone = -not (Test-Path -LiteralPath (Join-Path $root 'enrollment\bootstrap.json'))
    $watch = [Diagnostics.Stopwatch]::StartNew()
    Stop-Service -Name $name
    $stopped = Wait-State 'Stopped' 60
    Add-Result 'first_start_enrolls_samples_and_stops' ($bootstrapGone -and $stopped.ExitCode -eq 0 -and (Get-EnvelopeCount) -gt 0) @{ pid = $first.ProcessId; bootstrap_removed = $bootstrapGone; stop_ms = $watch.ElapsedMilliseconds; win32_exit_code = $stopped.ExitCode; envelopes = Get-EnvelopeCount }

    # 3. Restart on the same identity.
    Start-Service -Name $name
    $second = Wait-State 'Running' 30
    Start-Sleep -Seconds 30

    # 4. Crash: the SCM restarts the process, and the replacement signs new evidence.
    Stop-Process -Id $second.ProcessId -Force
    $watch.Restart()
    $deadline = [DateTime]::UtcNow.AddSeconds(60)
    do { Start-Sleep -Milliseconds 500; $third = Get-State } while (($third.State -ne 'Running' -or $third.ProcessId -eq $second.ProcessId -or $third.ProcessId -eq 0) -and [DateTime]::UtcNow -lt $deadline)
    $restartMs = $watch.ElapsedMilliseconds
    $boundary = Get-EnvelopeCount
    Start-Sleep -Seconds 30
    $after = Get-EnvelopeCount
    Add-Result 'killed_process_restarted_by_scm_and_signs' ($third.State -eq 'Running' -and $third.ProcessId -ne $second.ProcessId -and $after -gt $boundary) @{ killed_pid = $second.ProcessId; new_pid = $third.ProcessId; restart_ms = $restartMs; envelopes_at_restart = $boundary; envelopes_after_30s = $after }
    Stop-Service -Name $name
    $stopped = Wait-State 'Stopped' 60
    Add-Result 'restarted_service_stops_cleanly' ($stopped.ExitCode -eq 0) @{ win32_exit_code = $stopped.ExitCode }

    # 5. Lower the record cap while stopped. The next sample must retain the queue.
    $configPath = Join-Path $root 'service.json'
    $cfg = Get-Content -LiteralPath $configPath -Raw | ConvertFrom-Json
    $before = Get-EnvelopeCount
    $cfg.max_evidence_records = $before
    $cfg | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $configPath -Encoding utf8NoBOM
    Start-Service -Name $name
    $null = Wait-State 'Running' 30
    Start-Sleep -Seconds 25
    $retained = Get-EnvelopeCount
    Stop-Service -Name $name
    $s = Wait-State 'Stopped' 60
    $full = (Get-Content -LiteralPath $serviceLog -Raw).Contains('signed evidence spool full')
    Add-Result 'full_spool_retains_records' ($before -gt 0 -and $retained -eq $before -and $full -and $s.ExitCode -eq 0) @{ before = $before; retained = $retained; log_reports_full = $full }
    $null = Invoke-Sc @('failureflag', $name, '0')
    # 6. Unsupported runtime; failureflag is already off, so no restarts.
    $null = Invoke-Sc @('config', $name, 'obj=', 'LocalSystem')
    Start-AndExpectRefusal 'local_system_refused' 2 'refuses LocalSystem'
    $null = Invoke-Sc @('config', $name, 'obj=', 'NT AUTHORITY\LocalService', 'password=', '')
    $null = Invoke-Sc @('privs', $name, 'SeChangeNotifyPrivilege/SeImpersonatePrivilege')
    Start-AndExpectRefusal 'extra_privilege_refused' 2 'outside the documented privileges'
    $null = Invoke-Sc @('privs', $name, 'SeChangeNotifyPrivilege')
} catch {
    Add-Result 'script_error' $false @{ error = "$_" }
} finally {
    # 7. Evidence, then remove what this run created, even if copying fails.
    try {
        foreach ($file in Get-ChildItem -LiteralPath (Join-Path $root 'evidence') -File -ErrorAction SilentlyContinue) {
            Copy-Item -LiteralPath $file.FullName -Destination $out -Force
        }
        $identity = Join-Path $root 'identity'
        if (Test-Path -LiteralPath $identity) {
            $acl = [ordered]@{ directory_sddl = (Get-Acl -LiteralPath $identity).Sddl; files = @() }
            try { $acl.files = @(Get-ChildItem -LiteralPath $identity -Force -ErrorAction Stop | ForEach-Object Name) } catch { $acl.files = "administrator listing denied: $($_.Exception.Message)" }
            $acl | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $out 'identity-acl.json') -Encoding utf8NoBOM
        }
        $evidenceAcl = Join-Path $root 'evidence'
        if (Test-Path -LiteralPath $evidenceAcl) {
            [ordered]@{ evidence_sddl = (Get-Acl -LiteralPath $evidenceAcl).Sddl; root_sddl = (Get-Acl -LiteralPath $root).Sddl } |
                ConvertTo-Json | Set-Content -LiteralPath (Join-Path $out 'state-acl.json') -Encoding utf8NoBOM
        }
    } catch {
        Add-Result 'artifact_collection' $false @{ error = "$_" }
    } finally {
        # Both were absent at start, so whatever exists now is this run's.
        if ((Get-Service -Name $name -ErrorAction SilentlyContinue) -or (Test-Path -LiteralPath $root)) {
            & "$PSScriptRoot/Uninstall-EndpointService.ps1" -Root $root -PurgeState
        }
        $failed = @($steps | Where-Object { -not $_.passed })
        [ordered]@{ schema = 'device-audit.service-qualification.v1'; passed = $failed.Count -eq 0; steps = $steps } |
            ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Join-Path $out 'qualification.json') -Encoding utf8NoBOM
        Set-Content -LiteralPath (Join-Path $out 'qualification-done') -Value ''
        Write-Step "qualification finished; $($failed.Count) failed step(s)"
    }
}
if (@($steps | Where-Object { -not $_.passed }).Count -gt 0) { exit 1 }
