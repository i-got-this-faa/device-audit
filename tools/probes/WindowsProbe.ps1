#requires -Version 7.0
# Read-only development probes. This is not the endpoint diagnostic executor.
Set-StrictMode -Version Latest

function New-Reading {
    param([string]$Name, [string]$Unit, $Value, [string]$Instance = 'total',
        [string]$MissingReason = 'sensor_unavailable', [double]$Minimum = 0,
        [double]$Maximum = [double]::MaxValue)
    $number = 0.0
    $valid = $null -ne $Value -and [double]::TryParse([string]$Value,
        [Globalization.NumberStyles]::Float, [Globalization.CultureInfo]::InvariantCulture, [ref]$number)
    if ($valid -and ([double]::IsNaN($number) -or [double]::IsInfinity($number) -or
        $number -lt $Minimum -or $number -gt $Maximum)) {
        $valid = $false
        $MissingReason = 'collection_error'
    }
    [pscustomobject]@{
        name = $Name; instance = $Instance; unit = $Unit
        value = $(if ($valid) { [math]::Round($number, 4) } else { $null })
        missing_reason = $(if ($valid) { $null } else { $MissingReason })
    }
}

function Get-ProbeFailureReason {
    param([Management.Automation.ErrorRecord]$Record)
    # Use exception types/status, never localized error-message matching.
    $exception = $Record.Exception
    while ($null -ne $exception) {
        if ($exception -is [UnauthorizedAccessException] -or
            $exception.HResult -in -2147024891, -2147217405) { return 'permission_denied' }
        if ($exception -is [Microsoft.Management.Infrastructure.CimException]) {
            if ($exception.NativeErrorCode.ToString() -eq 'AccessDenied') { return 'permission_denied' }
            if ($exception.NativeErrorCode.ToString() -in 'InvalidClass', 'InvalidNamespace', 'NotFound', 'NotSupported') {
                return 'sensor_unavailable'
            }
        }
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

function Get-ProbeReadings {
    param([ValidateSet('cpu', 'memory', 'disk', 'network', 'battery', 'thermal', 'gpu', 'events')][string]$Source)
    switch ($Source) {
        cpu {
            $rows = @(Get-CimInstance -ClassName Win32_PerfFormattedData_PerfOS_Processor -Filter "Name='_Total'" -OperationTimeoutSec 5 -ErrorAction Stop)
            if ($rows.Count -eq 1) { New-Reading cpu_utilization percent $rows[0].PercentProcessorTime -Maximum 100 }
            else { New-Reading cpu_utilization percent $null }
        }
        memory {
            $os = Get-CimInstance -ClassName Win32_OperatingSystem -Property TotalVisibleMemorySize,FreePhysicalMemory -OperationTimeoutSec 3 -ErrorAction Stop
            New-Reading memory_used percent (Get-UsedPercent $os.TotalVisibleMemorySize $os.FreePhysicalMemory) -Maximum 100 -MissingReason collection_error
        }
        disk {
            $rows = @(Get-CimInstance -ClassName Win32_LogicalDisk -Filter 'DriveType=3' -Property Size,FreeSpace -OperationTimeoutSec 3 -ErrorAction Stop)
            if ($rows.Count -eq 0) { New-Reading disk_used percent $null }
            for ($i = 0; $i -lt [math]::Min($rows.Count, 32); $i++) {
                New-Reading disk_used percent (Get-UsedPercent $rows[$i].Size $rows[$i].FreeSpace) -Instance "disk-$i" -Maximum 100 -MissingReason collection_error
            }
        }
        network {
            $interfaces = @([Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces() | Where-Object {
                $_.OperationalStatus -eq 'Up' -and $_.NetworkInterfaceType -notin 'Loopback', 'Tunnel'
            } | Select-Object -First 32)
            if ($interfaces.Count -eq 0) {
                New-Reading network_received bytes_per_second $null -MissingReason not_applicable
                New-Reading network_sent bytes_per_second $null -MissingReason not_applicable
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
                    New-Reading network_received bytes_per_second (Get-CounterRate $before[$nic.Id].stats.BytesReceived $after.BytesReceived $seconds) -Instance "interface-$i" -MissingReason collection_error
                    New-Reading network_sent bytes_per_second (Get-CounterRate $before[$nic.Id].stats.BytesSent $after.BytesSent $seconds) -Instance "interface-$i" -MissingReason collection_error
                } catch {
                    New-Reading network_received bytes_per_second $null -Instance "interface-$i" -MissingReason (Get-ProbeFailureReason $_)
                    New-Reading network_sent bytes_per_second $null -Instance "interface-$i" -MissingReason (Get-ProbeFailureReason $_)
                }
            }
        }
        battery {
            $rows = @(Get-CimInstance -ClassName Win32_Battery -Property EstimatedChargeRemaining -OperationTimeoutSec 3 -ErrorAction Stop)
            if ($rows.Count -eq 0) { New-Reading battery_charge percent $null -MissingReason not_applicable }
            for ($i = 0; $i -lt [math]::Min($rows.Count, 8); $i++) {
                New-Reading battery_charge percent $rows[$i].EstimatedChargeRemaining -Instance "battery-$i" -Maximum 100
            }
        }
        thermal {
            $rows = @(Get-CimInstance -Namespace root/wmi -ClassName MSAcpi_ThermalZoneTemperature -Property CurrentTemperature -OperationTimeoutSec 3 -ErrorAction Stop)
            if ($rows.Count -eq 0) { New-Reading acpi_zone_temperature celsius $null }
            for ($i = 0; $i -lt [math]::Min($rows.Count, 32); $i++) {
                $value = $null
                if ($null -ne $rows[$i].CurrentTemperature -and $rows[$i].CurrentTemperature -gt 0) {
                    $value = [double]$rows[$i].CurrentTemperature / 10.0 - 273.15
                }
                New-Reading acpi_zone_temperature celsius $value -Instance "zone-$i" -Minimum -273.15
            }
        }
        gpu {
            # Query the already-installed vendor tool at its fixed system path.
            # No discovery via PATH, download, driver change, or power-mode change.
            $smi = Join-Path ([Environment]::SystemDirectory) 'nvidia-smi.exe'
            if (-not (Test-Path -LiteralPath $smi -PathType Leaf)) {
                New-Reading nvidia_gpu_utilization percent $null
                New-Reading nvidia_gpu_temperature celsius $null
                break
            }
            $lines = @(& $smi '--query-gpu=utilization.gpu,temperature.gpu' '--format=csv,noheader,nounits' 2>$null)
            if ($LASTEXITCODE -ne 0) { throw 'vendor_query_failed' }
            if ($lines.Count -eq 0) { throw 'empty_vendor_response' }
            for ($i = 0; $i -lt [math]::Min($lines.Count, 16); $i++) {
                $fields = $lines[$i].Split(',').Trim()
                if ($fields.Count -ne 2) { throw 'malformed_vendor_response' }
                New-Reading nvidia_gpu_utilization percent $fields[0] -Instance "nvidia-$i" -Maximum 100
                New-Reading nvidia_gpu_temperature celsius $fields[1] -Instance "nvidia-$i" -Minimum -273.15
            }
        }
        events {
            # Metadata only: no event messages, payloads, user names, or record IDs.
            foreach ($name in 'System', 'Application') {
                try {
                    $log = Get-WinEvent -ListLog $name -ErrorAction Stop
                    New-Reading event_log_enabled boolean ([int]$log.IsEnabled) -Instance $name -Maximum 1
                    New-Reading event_log_records count $log.RecordCount -Instance $name
                } catch {
                    New-Reading event_log_enabled boolean $null -Instance $name -MissingReason (Get-ProbeFailureReason $_)
                    New-Reading event_log_records count $null -Instance $name -MissingReason (Get-ProbeFailureReason $_)
                }
            }
        }
    }
}

function Get-WindowsProbeResult {
    param([ValidateSet('cpu', 'memory', 'disk', 'network', 'battery', 'thermal', 'gpu', 'events')][string]$Source)
    $providers = @{
        cpu = 'CIM:root/cimv2:Win32_PerfFormattedData_PerfOS_Processor.PercentProcessorTime(_Total)'
        memory = 'CIM:root/cimv2:Win32_OperatingSystem.TotalVisibleMemorySize,FreePhysicalMemory'
        disk = 'CIM:root/cimv2:Win32_LogicalDisk.Size,FreeSpace(DriveType=3)'
        network = '.NET:NetworkInterface.GetIPStatistics:250ms counter delta'
        battery = 'CIM:root/cimv2:Win32_Battery.EstimatedChargeRemaining'
        thermal = 'CIM:root/wmi:MSAcpi_ThermalZoneTemperature.CurrentTemperature'
        gpu = 'NVIDIA:nvidia-smi:utilization.gpu,temperature.gpu'
        events = 'Get-WinEvent:-ListLog System,Application (metadata only)'
    }
    $start = [DateTime]::UtcNow.ToString('o')
    $timer = [Diagnostics.Stopwatch]::StartNew()
    $failure = $null
    try { $readings = @(Get-ProbeReadings -Source $Source) }
    catch { $failure = Get-ProbeFailureReason $_; $readings = @() }
    [pscustomobject]@{
        source = $Source; provider = $providers[$Source]; started_at = $start
        completed_at = [DateTime]::UtcNow.ToString('o')
        query_ms = [math]::Round($timer.Elapsed.TotalMilliseconds, 3)
        failure_reason = $failure; readings = $readings
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
    $result = @{ source = $Source; failure_reason = 'worker_error'; readings = @() }
    $startedProcess = $false
    try {
        $null = $process.Start()
        $startedProcess = $true
        $stdout = $process.StandardOutput.ReadToEndAsync()
        $stderr = $process.StandardError.ReadToEndAsync()
        if (-not $process.WaitForExit($TimeoutMilliseconds)) {
            $process.Kill($true)
            $process.WaitForExit()
            $result.failure_reason = 'timeout'
        } elseif ($process.ExitCode -eq 0) {
            $payload = $stdout.GetAwaiter().GetResult()
            if ($payload.Length -gt 65536) { throw 'worker_output_too_large' }
            $result = $payload | ConvertFrom-Json -AsHashtable
        }
        # Errors may contain local identifiers; discard them, including on failure.
        $null = $stderr.GetAwaiter().GetResult()
    } catch {
        $result = @{ source = $Source; failure_reason = 'worker_error'; readings = @() }
    } finally {
        if ($startedProcess -and -not $process.HasExited) { $process.Kill($true); $process.WaitForExit() }
        $process.Dispose()
    }
    $result.worker_started_at = $started
    $result.worker_completed_at = [DateTime]::UtcNow.ToString('o')
    $result.worker_wall_ms = [math]::Round($timer.Elapsed.TotalMilliseconds, 3)
    return $result
}
