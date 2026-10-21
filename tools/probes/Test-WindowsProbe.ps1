#requires -Version 7.0
$ErrorActionPreference = 'Stop'
. "$PSScriptRoot/WindowsProbe.ps1"
$checks = 0
$sources = @('cpu', 'memory', 'disk', 'network', 'battery', 'thermal', 'gpu', 'events')

function Assert-True([bool]$Condition, [string]$Message) {
    if (-not $Condition) { throw $Message }
    $script:checks++
}

function Assert-CompleteReadings {
    param($Result, [string]$Source, [string]$Provenance = 'fixture')
    Assert-True ($Result.provider -ceq (Get-ProbeSourceProvider -Source $Source)) 'Source provider missing or changed'
    foreach ($metric in Get-ProbeMetricCatalog -Source $Source) {
        $matches = @($Result.readings | Where-Object { $_.name -ceq $metric.name })
        Assert-True ($matches.Count -gt 0) "Catalog metric missing: $Source/$($metric.name)"
        foreach ($reading in $matches) {
            Assert-True ($reading.unit -ceq $metric.unit -and $reading.provider -ceq $metric.provider) `
                "Metric unit/provider mismatch: $Source/$($metric.name)"
            Assert-True ($reading.provenance -ceq $Provenance) 'Reading provenance missing or changed'
        }
    }
}

function Assert-FailureReadings {
    param($Result, [string]$Source, [string]$Reason, [string]$Provenance = 'fixture')
    Assert-CompleteReadings -Result $Result -Source $Source -Provenance $Provenance
    foreach ($metric in Get-ProbeMetricCatalog -Source $Source) {
        $reading = @($Result.readings | Where-Object {
            $_.name -ceq $metric.name -and $_.instance -ceq $metric.instance
        })[0]
        Assert-True ($null -eq $reading.value -and $reading.missing_reason -ceq $Reason) `
            "Failure metric not explicit: $Source/$($metric.name)"
    }
}


foreach ($value in @($null, '', 'N/A', [double]::NaN, [double]::PositiveInfinity, -1, 101)) {
    $reading = New-Reading percent percent $value -Maximum 100
    $reading.provenance = 'fixture'
    Assert-True ($null -eq $reading.value -and $null -ne $reading.missing_reason) 'Missing/invalid metric became a measured number'
}
$zero = New-Reading cpu percent 0 -Maximum 100
$zero.provenance = 'fixture'
Assert-True ($zero.value -eq 0 -and $null -eq $zero.missing_reason) 'A real measured zero must be retained'
Assert-True ((Get-UsedPercent 100 25) -eq 75) 'Used-space conversion'
foreach ($pair in @(@($null, 0), @(0, 0), @(100, $null), @(100, -1), @(100, 101))) {
    Assert-True ($null -eq (Get-UsedPercent $pair[0] $pair[1])) 'Bad capacity became a healthy zero'
}
Assert-True ((Get-CounterRate 100 150 0.5) -eq 100) 'Rate must use elapsed seconds'
Assert-True ($null -eq (Get-CounterRate 150 100 1)) 'Counter reset must not yield a negative rate'
Assert-True ($null -eq (Get-CounterRate 100 150 0)) 'Zero interval must be unavailable'

# Mock only fixed read-only provider seams; test results are explicitly fixtures.
$script:mode = 'denied'
$script:eventLogCalls = [Collections.Generic.List[string]]::new()
$script:eventQueryCalls = [Collections.Generic.List[object]]::new()
$script:disableSystemLog = $false
function Get-CimInstance {
    param($ClassName, $Namespace, $Property, $Filter, $OperationTimeoutSec, $ErrorAction)
    switch ($script:mode) {
        denied { throw [UnauthorizedAccessException]::new('PRIVATE_IDENTIFIER_MUST_NOT_LEAK') }
        timeout { throw [TimeoutException]::new('PRIVATE_TIMEOUT_DETAIL_MUST_NOT_LEAK') }
        absent { return }
        nullBattery { return [pscustomobject]@{ EstimatedChargeRemaining = $null } }
        zeroBattery { return [pscustomobject]@{ EstimatedChargeRemaining = 0 } }
        badDisk { return [pscustomobject]@{ Size = 100; FreeSpace = 101 } }
        thermal { return [pscustomobject]@{ CurrentTemperature = 3000 } }
        gpuRows {
            if ($ClassName -eq 'Win32_PerfFormattedData_GPUPerformanceCounters_GPUEngine') {
                $rows = for ($i = 0; $i -lt 33; $i++) {
                    [pscustomobject]@{ Name = "PRIVATE_GPU_INSTANCE_$i"; UtilizationPercentage = $i }
                }
                return $rows
            }
            return
        }
        gpuBounds {
            if ($ClassName -eq 'Win32_PerfFormattedData_GPUPerformanceCounters_GPUEngine') {
                return [pscustomobject]@{ Name = 'PRIVATE_GPU_INSTANCE'; UtilizationPercentage = 101 }
            }
            return
        }
        gpuAbsent { return }
        default { return }
    }
}

function Get-WinEvent {
    param($ListProvider, $ListLog, [hashtable]$FilterHashtable, $MaxEvents, $ErrorAction)
    if ($PSBoundParameters.ContainsKey('ListProvider')) {
        switch ($ListProvider) {
            'Microsoft-Windows-WHEA-Logger' {
                return [pscustomobject]@{ LogLinks = @([pscustomobject]@{ LogName = 'System'; DisplayName = 'System'; IsImported = $false }) }
            }
            'disk' {
                return [pscustomobject]@{ LogLinks = @([pscustomobject]@{ LogName = 'Application'; DisplayName = 'Application'; IsImported = $false }) }
            }
            'Microsoft-Windows-Kernel-Power' {
                throw [System.Management.Automation.ErrorRecord]::new(
                    [InvalidOperationException]::new('PRIVATE_PROVIDER_NOT_FOUND'),
                    'NoMatchingProvidersFound,Microsoft.PowerShell.Commands.GetWinEventCommand',
                    [System.Management.Automation.ErrorCategory]::ObjectNotFound, $ListProvider)
            }
            'Application Error' {
                return [pscustomobject]@{ LogLinks = @([pscustomobject]@{ LogName = 'Application'; DisplayName = 'Application'; IsImported = $false }) }
            }
            'Windows Error Reporting' {
                return [pscustomobject]@{ LogLinks = @([pscustomobject]@{ LogName = 'Application'; DisplayName = 'Application'; IsImported = $false }) }
            }
        }
    }
    if ($PSBoundParameters.ContainsKey('ListLog')) {
        $script:eventLogCalls.Add($ListLog)
        return [pscustomobject]@{ IsEnabled = -not ($script:disableSystemLog -and $ListLog -eq 'System') }
    }
    if ($PSBoundParameters.ContainsKey('FilterHashtable')) {
        $script:eventQueryCalls.Add([pscustomobject]@{
            provider = $FilterHashtable.ProviderName; log = $FilterHashtable.LogName
            levels = @($FilterHashtable.Level); start_time = $FilterHashtable.StartTime; max_events = $MaxEvents
        })
        switch ($FilterHashtable.ProviderName) {
            'Microsoft-Windows-WHEA-Logger' {
                return [pscustomobject]@{ Message = 'PRIVATE_EVENT_PAYLOAD'; Id = 123456; RecordId = 987654 }
            }
            'Application Error' {
                throw [UnauthorizedAccessException]::new('PRIVATE_EVENT_ACCESS_ERROR')
            }
            'Windows Error Reporting' {
                throw [System.Management.Automation.ErrorRecord]::new(
                    [InvalidOperationException]::new('PRIVATE_NO_MATCH_DETAIL'),
                    'NoMatchingEventsFound,Microsoft.PowerShell.Commands.GetWinEventCommand',
                    [System.Management.Automation.ErrorCategory]::ObjectNotFound, $FilterHashtable.ProviderName)
            }
        }
    }
}

function Invoke-FixtureProbe([string]$Source) {
    $result = Get-WindowsProbeResult -Source $Source
    Assert-True ($result.provenance -ceq 'real') 'Actual wrapper result must be marked real before fixture tagging'
    foreach ($reading in $result.readings) {
        Assert-True ($reading.provenance -ceq 'real') 'Actual reading must be marked real before fixture tagging'
        $reading.provenance = 'fixture'
    }
    $result.provenance = 'fixture'
    return $result
}

function Join-Path {
    param([string]$Path, [string]$ChildPath)
    if ($ChildPath -eq 'nvidia-smi.exe') {
        return [IO.Path]::Combine([IO.Path]::GetTempPath(), 'fixture-nvidia-smi.exe')
    }
    return Microsoft.PowerShell.Management\Join-Path -Path $Path -ChildPath $ChildPath
}


function Test-Path {
    param([string]$LiteralPath, [string]$PathType)
    if ($LiteralPath -like '*nvidia-smi.exe') { return $false }
    return Microsoft.PowerShell.Management\Test-Path -LiteralPath $LiteralPath -PathType $PathType
}

$denied = Invoke-FixtureProbe cpu
Assert-True ($denied.failure_reason -eq 'permission_denied') 'Permission denial must be distinct'
Assert-FailureReadings -Result $denied -Source cpu -Reason permission_denied
Assert-True (($denied | ConvertTo-Json -Depth 8) -notmatch 'PRIVATE_IDENTIFIER') 'Raw provider error leaked'

$script:mode = 'timeout'
$timedOut = Invoke-FixtureProbe cpu
Assert-True ($timedOut.failure_reason -eq 'timeout') 'Source timeout must be distinct'
Assert-FailureReadings -Result $timedOut -Source cpu -Reason timeout
Assert-True (($timedOut | ConvertTo-Json -Depth 8) -notmatch 'PRIVATE_TIMEOUT_DETAIL') 'Raw timeout leaked'

$script:mode = 'absent'
$absent = Invoke-FixtureProbe battery
Assert-True ($absent.readings[0].missing_reason -eq 'not_applicable') 'Absent battery is not a measured zero'
$script:mode = 'nullBattery'
$nullBattery = Invoke-FixtureProbe battery
Assert-True ($null -eq $nullBattery.readings[0].value -and $nullBattery.readings[0].missing_reason) 'Null battery reading became zero'
$script:mode = 'zeroBattery'
$zeroBattery = Invoke-FixtureProbe battery
Assert-True ($zeroBattery.readings[0].value -eq 0 -and $null -eq $zeroBattery.readings[0].missing_reason) 'Battery zero must be retained'
$script:mode = 'badDisk'
$disk = Invoke-FixtureProbe disk
Assert-True ($disk.readings[0].missing_reason -eq 'collection_error') 'Invalid disk capacity must be explicit'
$script:mode = 'thermal'
$thermal = Invoke-FixtureProbe thermal
Assert-True ([math]::Abs($thermal.readings[0].value - 26.85) -lt 0.001) 'Thermal units must be tenths Kelvin to Celsius'

$script:mode = 'gpuRows'
$gpu = Invoke-FixtureProbe gpu
$genericGpu = @($gpu.readings | Where-Object { $_.name -ceq 'gpu_engine_utilization' })
Assert-True ($genericGpu.Count -eq 32) 'GPU engine results must be capped at 32'
Assert-True ($genericGpu[0].instance -eq 'engine-0' -and $genericGpu[31].instance -eq 'engine-31') `
    'GPU engine instances must be anonymous indexes'
Assert-True ($genericGpu[0].value -eq 0 -and $genericGpu[1].value -eq 1) 'Vendor-independent GPU rows were not measured'
Assert-True (($gpu | ConvertTo-Json -Depth 8) -notmatch 'PRIVATE_GPU_INSTANCE') 'GPU instance identifiers leaked'
$nvidiaMissing = @($gpu.readings | Where-Object { $_.name -eq 'nvidia_gpu_utilization' })[0]
Assert-True ($null -eq $nvidiaMissing.value -and $nvidiaMissing.missing_reason -eq 'not_applicable') `
    'Absent NVIDIA tool must not suppress generic GPU data'
$script:mode = 'gpuBounds'
$gpuBounds = Invoke-FixtureProbe gpu
$bounded = @($gpuBounds.readings | Where-Object { $_.name -eq 'gpu_engine_utilization' })[0]
Assert-True ($null -eq $bounded.value -and $bounded.missing_reason -eq 'collection_error') 'GPU utilization above 100 must be rejected'
$script:mode = 'gpuAbsent'
$gpuAbsent = Invoke-FixtureProbe gpu
$genericAbsent = @($gpuAbsent.readings | Where-Object { $_.name -eq 'gpu_engine_utilization' })[0]
Assert-True ($null -eq $genericAbsent.value -and $genericAbsent.missing_reason -eq 'not_applicable') `
    'Unavailable generic GPU inventory must be explicit'
Remove-Item Function:\Test-Path
Remove-Item Function:\Join-Path

$script:eventQueryCalls.Clear()
$script:eventLogCalls.Clear()
$events = Invoke-FixtureProbe events
Assert-CompleteReadings -Result $events -Source events
Assert-True ($events.failure_reason -eq $null) 'A partial event provider failure must not erase other results'
function Get-FixtureMetric($Result, [string]$Name) {
    @($Result.readings | Where-Object { $_.name -ceq $Name })[0]
}
$wheaEnabled = Get-FixtureMetric $events event_system_whea_logger_enabled
$wheaRecent = Get-FixtureMetric $events event_system_whea_logger_recent_error_present
Assert-True ($wheaEnabled.value -eq 1 -and $wheaRecent.value -eq 1) 'Registered WHEA source and recent event were not inventoried'
$diskEnabled = Get-FixtureMetric $events event_system_disk_enabled
$diskRecent = Get-FixtureMetric $events event_system_disk_recent_error_present
Assert-True ($diskEnabled.value -eq 0 -and $null -eq $diskRecent.value -and $diskRecent.missing_reason -eq 'not_applicable') `
    'Unassociated provider must be distinguished without querying its log'
$kernelMissing = Get-FixtureMetric $events event_system_kernel_power_enabled
$kernelRecent = Get-FixtureMetric $events event_system_kernel_power_recent_error_present
Assert-True ($null -eq $kernelMissing.value -and $kernelMissing.missing_reason -eq 'sensor_unavailable') `
    'Missing event provider must be explicit'
Assert-True ($null -eq $kernelRecent.value -and $kernelRecent.missing_reason -eq 'sensor_unavailable') `
    'Missing event provider read result must be explicit'
$appRecent = Get-FixtureMetric $events event_application_error_recent_error_present
Assert-True ($null -eq $appRecent.value -and $appRecent.missing_reason -eq 'permission_denied') `
    'Event read denial must remain null, not report no errors'
$werRecent = Get-FixtureMetric $events event_windows_error_reporting_recent_error_present
Assert-True ($werRecent.value -eq 0 -and $null -eq $werRecent.missing_reason) `
    'Exact no-matching-events result must be a measured zero'
Assert-True ($script:eventLogCalls.Count -eq 3 -and
    @($script:eventLogCalls | Where-Object { $_ -notin 'System', 'Application' }).Count -eq 0) `
    'Provider association must be checked against only its expected log'
Assert-True (@($script:eventQueryCalls | Where-Object { $_.provider -eq 'disk' -or $_.provider -eq 'Microsoft-Windows-Kernel-Power' }).Count -eq 0) `
    'Unassociated or unregistered providers must not be queried'
foreach ($query in $script:eventQueryCalls) {
    Assert-True ($query.log -in 'System', 'Application' -and
        $query.provider -in 'Microsoft-Windows-WHEA-Logger', 'disk', 'Microsoft-Windows-Kernel-Power', 'Application Error', 'Windows Error Reporting') `
        'Event query must use only the selected error sources'
    Assert-True ($query.max_events -eq 1 -and $query.levels.Count -eq 2 -and $query.levels[0] -eq 1 -and $query.levels[1] -eq 2) `
        'Event query must be bounded to one critical/error record'
    Assert-True ($query.start_time -le [DateTime]::UtcNow -and $query.start_time -ge [DateTime]::UtcNow.AddHours(-24).AddMinutes(-1)) `
        'Event query start time must be limited to the previous 24 hours'
}
Assert-True (($events | ConvertTo-Json -Depth 8) -notmatch 'PRIVATE_EVENT_PAYLOAD|PRIVATE_NO_MATCH_DETAIL|PRIVATE_EVENT_ACCESS_ERROR') `
    'Event payload or raw event query error leaked'
$script:disableSystemLog = $true
$script:eventQueryCalls.Clear()
$script:eventLogCalls.Clear()
$disabledEvents = Invoke-FixtureProbe events
$disabledWhea = Get-FixtureMetric $disabledEvents event_system_whea_logger_enabled
$disabledRecent = Get-FixtureMetric $disabledEvents event_system_whea_logger_recent_error_present
Assert-True ($disabledWhea.value -eq 0 -and $null -eq $disabledRecent.value -and
    $disabledRecent.missing_reason -eq 'not_applicable') 'Disabled event log must not be queried as an enabled source'
$script:disableSystemLog = $false
Remove-Item Function:\Get-CimInstance
Remove-Item Function:\Get-WinEvent

$rejected = $false
try { Get-WindowsProbeResult 'cpu; arbitrary-command' } catch { $rejected = $true }
Assert-True $rejected 'Unknown/command-like sources must be rejected'

# A failed process launch and timeout both return the full catalog as explicit null metrics.
$script:missingWorkerPath = Join-Path ([IO.Path]::GetTempPath()) ('missing-worker-' + [guid]::NewGuid().ToString('N') + '.exe')
function Get-Process {
    param([int]$Id)
    [pscustomobject]@{ Path = $script:missingWorkerPath }
}
$workerError = Invoke-IsolatedProbe -Source gpu
Assert-True ($workerError.failure_reason -eq 'worker_error') 'Worker launch failure must be explicit'
Assert-FailureReadings -Result $workerError -Source gpu -Reason worker_error -Provenance real
Remove-Item Function:\Get-Process

if ($IsWindows) {
    $workerTimeout = Invoke-IsolatedProbe -Source network -TimeoutMilliseconds 1
    Assert-True ($workerTimeout.failure_reason -eq 'timeout') 'Hung worker must be terminated with explicit timeout'
    Assert-FailureReadings -Result $workerTimeout -Source network -Reason timeout -Provenance real
    $after = Invoke-IsolatedProbe -Source battery
    Assert-True ($after.provider -ceq (Get-ProbeSourceProvider -Source battery) -and $after.provenance -eq 'real') `
        'Timeout must not prevent later source execution'
    Assert-CompleteReadings -Result $after -Source battery -Provenance real
}

function New-SyntheticReport {
    $sourceResults = foreach ($source in $script:sources) {
        $readings = foreach ($metric in Get-ProbeMetricCatalog -Source $source) {
            $value = if ($source -eq 'cpu' -and $metric.name -eq 'cpu_utilization') { 0 } else { $null }
            $reason = if ($null -eq $value) { 'sensor_unavailable' } else { $null }
            $reading = New-Reading -Name $metric.name -Unit $metric.unit -Provider $metric.provider `
                -Instance 'HOSTILE_INSTANCE_SENTINEL' -Value $value -MissingReason $reason
            $reading.provenance = 'fixture'
            $reading
        }
        $provider = Get-ProbeSourceProvider -Source $source
        [pscustomobject]@{
            source = $source; provider = $provider
            provenance = 'fixture'; readings = @($readings)
        }
    }
    [pscustomobject]@{
        schema_version = 'device-audit.windows-probe.v1'
        purpose = 'development_source_availability_and_probe_cost_only'
        provenance = 'fixture'; environment = @{ computer_name = 'HOSTILE_ENVIRONMENT_SENTINEL' }
        sweeps = @([pscustomobject]@{ index = 0; sources = @($sourceResults) })
    }
}

function Set-SyntheticReportProvenance($Report, [string]$Provenance) {
    $Report.provenance = $Provenance
    foreach ($sourceResult in $Report.sweeps[0].sources) {
        $sourceResult.provenance = $Provenance
        foreach ($reading in $sourceResult.readings) { $reading.provenance = $Provenance }
    }
}

$tempRoot = Join-Path ([IO.Path]::GetTempPath()) ('device-audit-probe-tests-' + [guid]::NewGuid().ToString('N'))
$null = New-Item -ItemType Directory -Path $tempRoot
try {
    $exporter = Join-Path $PSScriptRoot 'Export-WindowsProbeEvidence.ps1'
    $fixturePath = Join-Path $tempRoot 'fixture-report.json'
    $realShapedPath = Join-Path $tempRoot 'real-shaped-report.json'
    $evidencePath = Join-Path $tempRoot 'evidence.md'
    $fixtureReport = New-SyntheticReport
    Assert-True ($fixtureReport.provenance -eq 'fixture') 'Synthetic report must remain fixture-tagged'
    foreach ($sourceResult in $fixtureReport.sweeps[0].sources) {
        Assert-True ($sourceResult.provenance -eq 'fixture') 'Synthetic source must remain fixture-tagged'
        foreach ($reading in $sourceResult.readings) {
            Assert-True ($reading.provenance -eq 'fixture') 'Synthetic reading must remain fixture-tagged'
        }
    }
    [IO.File]::WriteAllText($fixturePath, ($fixtureReport | ConvertTo-Json -Depth 16))
    $fixtureRejected = $false
    try { & $exporter -ReportPath $fixturePath -OutputPath $evidencePath } catch { $fixtureRejected = $true }
    Assert-True $fixtureRejected 'Evidence exporter must reject fixture reports'
    Assert-True (-not [IO.File]::Exists($evidencePath)) 'Rejected fixture must not create evidence output'

    $realShaped = New-SyntheticReport
    Set-SyntheticReportProvenance $realShaped 'real'
    [IO.File]::WriteAllText($realShapedPath, ($realShaped | ConvertTo-Json -Depth 16))
    & $exporter -ReportPath $realShapedPath -OutputPath $evidencePath
    $evidence = [IO.File]::ReadAllText($evidencePath)
    Assert-True ($evidence.Contains('| cpu | cpu_utilization |') -and $evidence.Contains('0 to 0')) `
        'Minimized evidence must retain a measured numeric zero'
    Assert-True ($evidence.Contains('sensor_unavailable')) 'Minimized evidence must retain missing reasons'
    Assert-True ($evidence -notmatch 'HOSTILE_ENVIRONMENT_SENTINEL|HOSTILE_INSTANCE_SENTINEL') `
        'Environment or instance strings leaked into minimized evidence'

    $invalidUnit = New-SyntheticReport
    Set-SyntheticReportProvenance $invalidUnit 'real'
    $invalidUnit.sweeps[0].sources[0].readings[0].unit = 'hostile_unit'
    $invalidUnitPath = Join-Path $tempRoot 'invalid-unit.json'
    [IO.File]::WriteAllText($invalidUnitPath, ($invalidUnit | ConvertTo-Json -Depth 16))
    $invalidUnitRejected = $false
    try { & $exporter -ReportPath $invalidUnitPath -OutputPath (Join-Path $tempRoot 'invalid-unit.md') } catch { $invalidUnitRejected = $true }
    Assert-True $invalidUnitRejected 'Evidence exporter must reject invalid units'

    $nullUnit = New-SyntheticReport
    Set-SyntheticReportProvenance $nullUnit 'real'
    $nullUnit.sweeps[0].sources[0].readings[0].unit = $null
    $nullUnitPath = Join-Path $tempRoot 'null-unit.json'
    [IO.File]::WriteAllText($nullUnitPath, ($nullUnit | ConvertTo-Json -Depth 16))
    $nullUnitRejected = $false
    try { & $exporter -ReportPath $nullUnitPath -OutputPath (Join-Path $tempRoot 'null-unit.md') } catch { $nullUnitRejected = $true }
    Assert-True $nullUnitRejected 'Evidence exporter must reject null units'

    $overwriteRejected = $false
    try { & $exporter -ReportPath $realShapedPath -OutputPath $evidencePath } catch { $overwriteRejected = $true }
    Assert-True $overwriteRejected 'Evidence exporter must reject overwrites'
} finally {
    if (Test-Path -LiteralPath $tempRoot) { Remove-Item -LiteralPath $tempRoot -Recurse -Force }
}

Write-Host 'fixture-driven export regression, not Windows evidence'
Write-Host "PASS: $checks Windows probe checks"
