#requires -Version 7.0
# Read-only development probes. This is not the endpoint diagnostic executor.
Set-StrictMode -Version Latest

function New-Reading {
    param([string]$Name, [string]$Unit, $Value, [string]$Instance = 'total',
        [string]$MissingReason = 'sensor_unavailable', [double]$Minimum = 0,
        [double]$Maximum = [double]::MaxValue, [string]$Provider = 'unspecified')
    $number = 0.0
    $valid = $null -ne $Value -and [double]::TryParse([string]$Value,
        [Globalization.NumberStyles]::Float, [Globalization.CultureInfo]::InvariantCulture, [ref]$number)
    if ($valid -and ([double]::IsNaN($number) -or [double]::IsInfinity($number) -or
        $number -lt $Minimum -or $number -gt $Maximum)) {
        $valid = $false
        $MissingReason = 'collection_error'
    }
    [pscustomobject]@{
        name = $Name; instance = $Instance; unit = $Unit; provider = $Provider
        provenance = 'real'
        value = $(if ($valid) { [math]::Round($number, 4) } else { $null })
        missing_reason = $(if ($valid) { $null } else { $MissingReason })
    }
}

function Get-ProbeFailureReason {
    param([Management.Automation.ErrorRecord]$Record)
    # Use exception types/status, never localized error-message matching.
    $category = if ($null -ne $Record.CategoryInfo) { $Record.CategoryInfo.Category.ToString() } else { '' }
    if ($category -eq 'PermissionDenied') { return 'permission_denied' }
    if ($category -eq 'OperationTimeout') { return 'timeout' }
    if ($category -eq 'ObjectNotFound' -or
        $Record.FullyQualifiedErrorId -ceq 'NoMatchingProvidersFound,Microsoft.PowerShell.Commands.GetWinEventCommand') {
        return 'sensor_unavailable'
    }
    $exception = $Record.Exception
    while ($null -ne $exception) {
        if ($exception -is [UnauthorizedAccessException] -or $exception.HResult -in -2147024891, -2147217405) {
            return 'permission_denied'
        }
        if ($exception -is [TimeoutException] -or $exception -is [OperationCanceledException]) { return 'timeout' }
        if ($exception -is [Microsoft.Management.Infrastructure.CimException]) {
            if ($exception.NativeErrorCode.ToString() -eq 'AccessDenied') { return 'permission_denied' }
            if ($exception.NativeErrorCode.ToString() -in 'TimedOut', 'Timeout', 'OperationTimedOut') { return 'timeout' }
            if ($exception.NativeErrorCode.ToString() -in 'InvalidClass', 'InvalidNamespace', 'NotFound', 'NotSupported') {
                return 'sensor_unavailable'
            }
        }
        if ($exception -is [System.Management.Automation.ItemNotFoundException] -or
            $category -eq 'ObjectNotFound') { return 'sensor_unavailable' }
        $exception = $exception.InnerException
    }
    return 'collection_error'
}

function Get-UsedPercent {
    param($Total, $Free)
    if ($null -eq $Total -or $null -eq $Free -or $Total -le 0 -or $Free -lt 0 -or $Free -gt $Total) {
        return $null
    }
    return 100.0 * ([double]$Total - [double]$Free) / [double]$Total
}

function Get-CounterRate {
    param($Before, $After, [double]$Seconds)
    if ($null -eq $Before -or $null -eq $After -or $Seconds -le 0 -or $After -lt $Before) { return $null }
    return ([double]$After - [double]$Before) / $Seconds
}

function Get-ProbeSourceProvider {
    param([ValidateSet('cpu', 'memory', 'disk', 'network', 'battery', 'thermal', 'gpu', 'events')][string]$Source)
    switch ($Source) {
        cpu { 'CIM:root/cimv2:Win32_PerfFormattedData_PerfOS_Processor.PercentProcessorTime(_Total)' }
        memory { 'CIM:root/cimv2:Win32_OperatingSystem.TotalVisibleMemorySize,FreePhysicalMemory' }
        disk { 'CIM:root/cimv2:Win32_LogicalDisk.Size,FreeSpace(DriveType=3)' }
        network { '.NET:NetworkInterface.GetIPStatistics:250ms counter delta' }
        battery { 'CIM:root/cimv2:Win32_Battery.EstimatedChargeRemaining' }
        thermal { 'CIM:root/wmi:MSAcpi_ThermalZoneTemperature.CurrentTemperature' }
        gpu { 'CIM:root/cimv2:Win32_PerfFormattedData_GPUPerformanceCounters_GPUEngine.UtilizationPercentage; NVIDIA:nvidia-smi:utilization.gpu,temperature.gpu' }
        events { 'Get-WinEvent:-ListProvider/-ListLog System,Application; bounded Level 1,2 query (metadata/boolean only)' }
    }
}

function Get-ProbeEventCandidates {
    @(
        [pscustomobject]@{ name = 'system_whea_logger'; provider = 'Microsoft-Windows-WHEA-Logger'; log = 'System'; instance = 'system-whea' }
        [pscustomobject]@{ name = 'system_disk'; provider = 'disk'; log = 'System'; instance = 'system-disk' }
        [pscustomobject]@{ name = 'system_kernel_power'; provider = 'Microsoft-Windows-Kernel-Power'; log = 'System'; instance = 'system-kernel-power' }
        [pscustomobject]@{ name = 'application_error'; provider = 'Application Error'; log = 'Application'; instance = 'application-error' }
        [pscustomobject]@{ name = 'windows_error_reporting'; provider = 'Windows Error Reporting'; log = 'Application'; instance = 'application-wer' }
    )
}
function Get-ProbeMetricCatalog {
    param([ValidateSet('cpu', 'memory', 'disk', 'network', 'battery', 'thermal', 'gpu', 'events')][string]$Source)
    $catalog = [Collections.Generic.List[object]]::new()
    switch ($Source) {
        cpu {
            $catalog.Add([pscustomobject]@{ name = 'cpu_utilization'; unit = 'percent'; provider = 'CIM:root/cimv2:Win32_PerfFormattedData_PerfOS_Processor.PercentProcessorTime'; instance = 'total' })
        }
        memory {
            $catalog.Add([pscustomobject]@{ name = 'memory_used'; unit = 'percent'; provider = 'CIM:root/cimv2:Win32_OperatingSystem.TotalVisibleMemorySize,FreePhysicalMemory'; instance = 'total' })
        }
        disk {
            $catalog.Add([pscustomobject]@{ name = 'disk_used'; unit = 'percent'; provider = 'CIM:root/cimv2:Win32_LogicalDisk.Size,FreeSpace(DriveType=3)'; instance = 'disk-0' })
        }
        network {
            $catalog.Add([pscustomobject]@{ name = 'network_received'; unit = 'bytes_per_second'; provider = '.NET:NetworkInterface.GetIPStatistics:250ms counter delta'; instance = 'interface-0' })
            $catalog.Add([pscustomobject]@{ name = 'network_sent'; unit = 'bytes_per_second'; provider = '.NET:NetworkInterface.GetIPStatistics:250ms counter delta'; instance = 'interface-0' })
        }
        battery {
            $catalog.Add([pscustomobject]@{ name = 'battery_charge'; unit = 'percent'; provider = 'CIM:root/cimv2:Win32_Battery.EstimatedChargeRemaining'; instance = 'battery-0' })
        }
        thermal {
            $catalog.Add([pscustomobject]@{ name = 'acpi_zone_temperature'; unit = 'celsius'; provider = 'CIM:root/wmi:MSAcpi_ThermalZoneTemperature.CurrentTemperature'; instance = 'zone-0' })
        }
        gpu {
            $catalog.Add([pscustomobject]@{ name = 'gpu_engine_utilization'; unit = 'percent'; provider = 'CIM:root/cimv2:Win32_PerfFormattedData_GPUPerformanceCounters_GPUEngine.UtilizationPercentage'; instance = 'engine-0' })
            $catalog.Add([pscustomobject]@{ name = 'nvidia_gpu_utilization'; unit = 'percent'; provider = 'NVIDIA:nvidia-smi:utilization.gpu'; instance = 'nvidia-0' })
            $catalog.Add([pscustomobject]@{ name = 'nvidia_gpu_temperature'; unit = 'celsius'; provider = 'NVIDIA:nvidia-smi:temperature.gpu'; instance = 'nvidia-0' })
        }
        events {
            foreach ($candidate in Get-ProbeEventCandidates) {
                $catalog.Add([pscustomobject]@{
                    name = "event_$($candidate.name)_enabled"; unit = 'boolean'
                    provider = $candidate.provider; instance = $candidate.instance
                })
                $catalog.Add([pscustomobject]@{
                    name = "event_$($candidate.name)_recent_error_present"; unit = 'boolean'
                    provider = $candidate.provider; instance = $candidate.instance
                })
            }
        }
    }
    return $catalog.ToArray()
}

function New-ProbeReading {
    param($Metric, $Value, [string]$Instance, [string]$MissingReason = 'sensor_unavailable',
        [double]$Minimum = 0, [double]$Maximum = [double]::MaxValue)
    if ([string]::IsNullOrEmpty($Instance)) { $Instance = $Metric.instance }
    New-Reading -Name $Metric.name -Unit $Metric.unit -Provider $Metric.provider -Value $Value `
        -Instance $Instance -MissingReason $MissingReason -Minimum $Minimum -Maximum $Maximum
}

function New-ProbeFailureReadings {
    param([ValidateSet('cpu', 'memory', 'disk', 'network', 'battery', 'thermal', 'gpu', 'events')][string]$Source,
        [ValidateSet('sensor_unavailable', 'not_applicable', 'permission_denied', 'collection_error', 'timeout', 'worker_error')][string]$Reason)
    foreach ($metric in Get-ProbeMetricCatalog -Source $Source) {
        New-ProbeReading -Metric $metric -Value $null -MissingReason $Reason
    }
}


function Get-ProbeReadings {
    param([ValidateSet('cpu', 'memory', 'disk', 'network', 'battery', 'thermal', 'gpu', 'events')][string]$Source)
    $catalog = @(Get-ProbeMetricCatalog -Source $Source)
    switch ($Source) {
        cpu {
            $rows = @(Get-CimInstance -ClassName Win32_PerfFormattedData_PerfOS_Processor -Filter "Name='_Total'" -OperationTimeoutSec 5 -ErrorAction Stop)
            if ($rows.Count -eq 1) {
                New-ProbeReading -Metric $catalog[0] -Value $rows[0].PercentProcessorTime -Maximum 100
            } else {
                New-ProbeReading -Metric $catalog[0] -Value $null
            }
        }
        memory {
            $os = Get-CimInstance -ClassName Win32_OperatingSystem -Property TotalVisibleMemorySize,FreePhysicalMemory -OperationTimeoutSec 3 -ErrorAction Stop
            New-ProbeReading -Metric $catalog[0] -Value (Get-UsedPercent $os.TotalVisibleMemorySize $os.FreePhysicalMemory) `
                -Maximum 100 -MissingReason collection_error
        }
        disk {
            $rows = @(Get-CimInstance -ClassName Win32_LogicalDisk -Filter 'DriveType=3' -Property Size,FreeSpace -OperationTimeoutSec 3 -ErrorAction Stop)
            if ($rows.Count -eq 0) {
                New-ProbeReading -Metric $catalog[0] -Value $null -MissingReason not_applicable
            }
            for ($i = 0; $i -lt [math]::Min($rows.Count, 32); $i++) {
                New-ProbeReading -Metric $catalog[0] -Value (Get-UsedPercent $rows[$i].Size $rows[$i].FreeSpace) `
                    -Instance "disk-$i" -Maximum 100 -MissingReason collection_error
            }
        }
        network {
            $interfaces = @([Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces() | Where-Object {
                $_.OperationalStatus -eq 'Up' -and $_.NetworkInterfaceType -notin 'Loopback', 'Tunnel'
            } | Select-Object -First 32)
            if ($interfaces.Count -eq 0) {
                New-ProbeReading -Metric $catalog[0] -Value $null -MissingReason not_applicable
                New-ProbeReading -Metric $catalog[1] -Value $null -MissingReason not_applicable
                break
            }
            $before = @{}
            $clock = [Diagnostics.Stopwatch]::StartNew()
            foreach ($nic in $interfaces) {
                try { $before[$nic.Id] = @{ stats = $nic.GetIPStatistics(); time = $clock.Elapsed.TotalSeconds } }
                catch { $before[$nic.Id] = $null }
            }
            Start-Sleep -Milliseconds 250
            for ($i = 0; $i -lt $interfaces.Count; $i++) {
                $nic = $interfaces[$i]
                try {
                    if ($null -eq $before[$nic.Id] -or $nic.OperationalStatus -ne 'Up') { throw 'interface_unavailable' }
                    $after = $nic.GetIPStatistics()
                    $seconds = $clock.Elapsed.TotalSeconds - $before[$nic.Id].time
                    New-ProbeReading -Metric $catalog[0] -Value (Get-CounterRate $before[$nic.Id].stats.BytesReceived $after.BytesReceived $seconds) `
                        -Instance "interface-$i" -MissingReason collection_error
                    New-ProbeReading -Metric $catalog[1] -Value (Get-CounterRate $before[$nic.Id].stats.BytesSent $after.BytesSent $seconds) `
                        -Instance "interface-$i" -MissingReason collection_error
                } catch {
                    $reason = Get-ProbeFailureReason $_
                    New-ProbeReading -Metric $catalog[0] -Value $null -Instance "interface-$i" -MissingReason $reason
                    New-ProbeReading -Metric $catalog[1] -Value $null -Instance "interface-$i" -MissingReason $reason
                }
            }
        }
        battery {
            $rows = @(Get-CimInstance -ClassName Win32_Battery -Property EstimatedChargeRemaining -OperationTimeoutSec 3 -ErrorAction Stop)
            if ($rows.Count -eq 0) {
                New-ProbeReading -Metric $catalog[0] -Value $null -MissingReason not_applicable
            }
            for ($i = 0; $i -lt [math]::Min($rows.Count, 8); $i++) {
                New-ProbeReading -Metric $catalog[0] -Value $rows[$i].EstimatedChargeRemaining `
                    -Instance "battery-$i" -Maximum 100
            }
        }
        thermal {
            $rows = @(Get-CimInstance -Namespace root/wmi -ClassName MSAcpi_ThermalZoneTemperature -Property CurrentTemperature -OperationTimeoutSec 3 -ErrorAction Stop)
            if ($rows.Count -eq 0) {
                New-ProbeReading -Metric $catalog[0] -Value $null -MissingReason not_applicable
            }
            for ($i = 0; $i -lt [math]::Min($rows.Count, 32); $i++) {
                $value = $null
                if ($null -ne $rows[$i].CurrentTemperature -and $rows[$i].CurrentTemperature -gt 0) {
                    $value = [double]$rows[$i].CurrentTemperature / 10.0 - 273.15
                }
                New-ProbeReading -Metric $catalog[0] -Value $value -Instance "zone-$i" -Minimum -273.15
            }
        }
        gpu {
            try {
                $rows = @(Get-CimInstance -ClassName Win32_PerfFormattedData_GPUPerformanceCounters_GPUEngine `
                    -Property UtilizationPercentage -OperationTimeoutSec 5 -ErrorAction Stop)
                if ($rows.Count -eq 0) {
                    New-ProbeReading -Metric $catalog[0] -Value $null -MissingReason not_applicable
                }
                for ($i = 0; $i -lt [math]::Min($rows.Count, 32); $i++) {
                    New-ProbeReading -Metric $catalog[0] -Value $rows[$i].UtilizationPercentage `
                        -Instance "engine-$i" -Maximum 100
                }
            } catch {
                New-ProbeReading -Metric $catalog[0] -Value $null -MissingReason (Get-ProbeFailureReason $_)
            }

            # Query the installed vendor tool at its fixed system path; never discover or install it.
            try {
                $smi = Join-Path ([Environment]::SystemDirectory) 'nvidia-smi.exe'
                if (-not (Test-Path -LiteralPath $smi -PathType Leaf)) {
                    New-ProbeReading -Metric $catalog[1] -Value $null -MissingReason not_applicable
                    New-ProbeReading -Metric $catalog[2] -Value $null -MissingReason not_applicable
                    break
                }
                $lines = @(& $smi '--query-gpu=utilization.gpu,temperature.gpu' '--format=csv,noheader,nounits' 2>$null)
                if ($LASTEXITCODE -ne 0 -or $lines.Count -eq 0) { throw 'vendor_query_failed' }
                $vendorRows = [Collections.Generic.List[object]]::new()
                for ($i = 0; $i -lt [math]::Min($lines.Count, 16); $i++) {
                    $fields = @(([string]$lines[$i]).Split(',') | ForEach-Object { $_.Trim() })
                    if ($fields.Count -ne 2) { throw 'malformed_vendor_response' }
                    $vendorRows.Add([pscustomobject]@{ utilization = $fields[0]; temperature = $fields[1]; instance = "nvidia-$i" })
                }
                foreach ($row in $vendorRows) {
                    New-ProbeReading -Metric $catalog[1] -Value $row.utilization -Instance $row.instance -Maximum 100
                    New-ProbeReading -Metric $catalog[2] -Value $row.temperature -Instance $row.instance -Minimum -273.15
                }
            } catch {
                $reason = Get-ProbeFailureReason $_
                New-ProbeReading -Metric $catalog[1] -Value $null -MissingReason $reason
                New-ProbeReading -Metric $catalog[2] -Value $null -MissingReason $reason
            }
        }
        events {
            $metricIndex = 0
            foreach ($candidate in Get-ProbeEventCandidates) {
                $enabledMetric = $catalog[$metricIndex]
                $recentMetric = $catalog[$metricIndex + 1]
                $metricIndex += 2
                try {
                    $metadata = Get-WinEvent -ListProvider $candidate.provider -ErrorAction Stop
                    if ($null -eq $metadata) {
                        New-ProbeReading -Metric $enabledMetric -Value $null -Instance $candidate.instance -MissingReason sensor_unavailable
                        New-ProbeReading -Metric $recentMetric -Value $null -Instance $candidate.instance -MissingReason sensor_unavailable
                        continue
                    }
                    $links = @($metadata.LogLinks | Where-Object { $_.LogName -ceq $candidate.log })
                    if ($links.Count -eq 0) {
                        New-ProbeReading -Metric $enabledMetric -Value 0 -Instance $candidate.instance -Maximum 1
                        New-ProbeReading -Metric $recentMetric -Value $null -Instance $candidate.instance -MissingReason not_applicable
                        continue
                    }
                    $log = Get-WinEvent -ListLog $candidate.log -ErrorAction Stop
                    $enabled = [bool]$log.IsEnabled
                    New-ProbeReading -Metric $enabledMetric -Value ([int]$enabled) -Instance $candidate.instance -Maximum 1
                    if (-not $enabled) {
                        New-ProbeReading -Metric $recentMetric -Value $null -Instance $candidate.instance -MissingReason not_applicable
                        continue
                    }
                } catch {
                    $reason = Get-ProbeFailureReason $_
                    New-ProbeReading -Metric $enabledMetric -Value $null -Instance $candidate.instance -MissingReason $reason
                    New-ProbeReading -Metric $recentMetric -Value $null -Instance $candidate.instance -MissingReason $reason
                    continue
                }

                try {
                    $filter = @{
                        LogName = $candidate.log; ProviderName = $candidate.provider
                        Level = @(1, 2); StartTime = [DateTime]::UtcNow.AddHours(-24)
                    }
                    $events = @(Get-WinEvent -FilterHashtable $filter -MaxEvents 1 -ErrorAction Stop)
                    New-ProbeReading -Metric $recentMetric -Value ([int]($events.Count -gt 0)) -Instance $candidate.instance -Maximum 1
                } catch {
                    if ($_.FullyQualifiedErrorId -ceq 'NoMatchingEventsFound,Microsoft.PowerShell.Commands.GetWinEventCommand') {
                        New-ProbeReading -Metric $recentMetric -Value 0 -Instance $candidate.instance -Maximum 1
                    } else {
                        New-ProbeReading -Metric $recentMetric -Value $null -Instance $candidate.instance `
                            -MissingReason (Get-ProbeFailureReason $_)
                    }
                }
            }
        }
    }
}

function Test-ProbeReadingsComplete {
    param($Readings, [ValidateSet('cpu', 'memory', 'disk', 'network', 'battery', 'thermal', 'gpu', 'events')][string]$Source)
    $items = @($Readings)
    if ($items.Count -eq 0) { return $false }
    foreach ($metric in Get-ProbeMetricCatalog -Source $Source) {
        if (@($items | Where-Object { $_.name -ceq $metric.name -and $_.instance -ceq $metric.instance }).Count -eq 0) {
            return $false
        }
    }
    return $true
}

function New-ProbeFailureResult {
    param([ValidateSet('cpu', 'memory', 'disk', 'network', 'battery', 'thermal', 'gpu', 'events')][string]$Source,
        [ValidateSet('sensor_unavailable', 'not_applicable', 'permission_denied', 'collection_error', 'timeout', 'worker_error')][string]$Reason,
        [string]$StartedAt, [string]$CompletedAt, $QueryMilliseconds)
    $provider = Get-ProbeSourceProvider -Source $Source
    [pscustomobject]@{
        source = $Source; provider = $provider
        started_at = $StartedAt; completed_at = $CompletedAt; query_ms = $QueryMilliseconds
        failure_reason = $Reason; provenance = 'real'
        readings = @(New-ProbeFailureReadings -Source $Source -Reason $Reason)
    }
}

function Get-WindowsProbeResult {
    param([ValidateSet('cpu', 'memory', 'disk', 'network', 'battery', 'thermal', 'gpu', 'events')][string]$Source)
    $start = [DateTime]::UtcNow.ToString('o')
    $timer = [Diagnostics.Stopwatch]::StartNew()
    $failure = $null
    try {
        $readings = @(Get-ProbeReadings -Source $Source)
        if (-not (Test-ProbeReadingsComplete -Readings $readings -Source $Source)) {
            throw 'incomplete_probe_result'
        }
    } catch {
        $failure = Get-ProbeFailureReason $_
        $readings = @(New-ProbeFailureReadings -Source $Source -Reason $failure)
    }
    $provider = Get-ProbeSourceProvider -Source $Source
    [pscustomobject]@{
        source = $Source; provider = $provider; started_at = $start
        completed_at = [DateTime]::UtcNow.ToString('o')
        query_ms = [math]::Round($timer.Elapsed.TotalMilliseconds, 3)
        failure_reason = $failure; provenance = 'real'; readings = $readings
    }
}


function Invoke-IsolatedProbe {
    param([ValidateSet('cpu', 'memory', 'disk', 'network', 'battery', 'thermal', 'gpu', 'events')][string]$Source,
        [ValidateRange(1, 30000)][int]$TimeoutMilliseconds = 10000)
    $info = [Diagnostics.ProcessStartInfo]::new((Get-Process -Id $PID).Path)
    $info.UseShellExecute = $false
    $info.CreateNoWindow = $true
    $info.RedirectStandardOutput = $true
    $info.RedirectStandardError = $true
    foreach ($arg in @('-NoLogo', '-NoProfile', '-NonInteractive', '-File',
        "$PSScriptRoot/Invoke-WindowsProbeWorker.ps1", '-Source', $Source)) { $info.ArgumentList.Add($arg) }
    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $info
    $timer = [Diagnostics.Stopwatch]::StartNew()
    $started = [DateTime]::UtcNow.ToString('o')
    $failure = 'worker_error'
    $result = $null
    $startedProcess = $false
    try {
        if (-not $process.Start()) { throw 'worker_start_failed' }
        $startedProcess = $true
        $stdout = $process.StandardOutput.ReadToEndAsync()
        $stderr = $process.StandardError.ReadToEndAsync()
        if (-not $process.WaitForExit($TimeoutMilliseconds)) {
            if (-not $process.HasExited) {
                try { $process.Kill($true) } catch { if (-not $process.HasExited) { throw } }
            }
            $process.WaitForExit()
            $failure = 'timeout'
        } elseif ($process.ExitCode -eq 0) {
            $payload = $stdout.GetAwaiter().GetResult()
            if ($payload.Length -gt 65536) { throw 'worker_output_too_large' }
            $workerResult = $payload | ConvertFrom-Json -AsHashtable -ErrorAction Stop
            if ($null -eq $workerResult -or $workerResult.source -cne $Source -or
                $workerResult.provider -cne (Get-ProbeSourceProvider -Source $Source) -or
                $workerResult.provenance -cne 'real' -or
                -not (Test-ProbeReadingsComplete -Readings $workerResult.readings -Source $Source)) {
                throw 'invalid_worker_result'
            }
            foreach ($reading in $workerResult.readings) {
                if ($reading.provenance -cne 'real') { throw 'invalid_worker_result' }
            }
            $result = $workerResult
        }
        # Errors may contain local identifiers; discard them, including on failure.
        $null = $stderr.GetAwaiter().GetResult()
    } catch {
        $failure = 'worker_error'
        $result = $null
    } finally {
        if ($startedProcess -and -not $process.HasExited) {
            try { $process.Kill($true); $process.WaitForExit() } catch { }
        }
        $process.Dispose()
    }

    $completed = [DateTime]::UtcNow.ToString('o')
    if ($null -eq $result) {
        $result = New-ProbeFailureResult -Source $Source -Reason $failure -StartedAt $started `
            -CompletedAt $completed -QueryMilliseconds $null
    }
    $result | Add-Member worker_started_at $started -Force
    $result | Add-Member worker_completed_at $completed -Force
    $result | Add-Member worker_wall_ms ([math]::Round($timer.Elapsed.TotalMilliseconds, 3)) -Force
    return $result
}
