#requires -Version 7.0
param([Parameter(Mandatory)][ValidateSet('cpu', 'memory', 'disk', 'network', 'battery', 'thermal', 'gpu', 'events')][string]$Source)
$ErrorActionPreference = 'Stop'
. "$PSScriptRoot/WindowsProbe.ps1"
$result = Get-WindowsProbeResult -Source $Source
$process = Get-Process -Id $PID
$result | Add-Member worker_cpu_ms ([math]::Round($process.TotalProcessorTime.TotalMilliseconds, 3))
$result | Add-Member worker_peak_working_set_bytes $process.PeakWorkingSet64
$result | ConvertTo-Json -Depth 8 -Compress
