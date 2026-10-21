#requires -Version 7.0
$ErrorActionPreference = 'Stop'
. "$PSScriptRoot/WindowsProbe.ps1"
$checks = 0
function Assert-True([bool]$Condition, [string]$Message) {
    if (-not $Condition) { throw $Message }
    $script:checks++
}
foreach ($value in @($null, '', 'N/A', [double]::NaN, [double]::PositiveInfinity, -1, 101)) {
    $reading = New-Reading percent percent $value -Maximum 100
    Assert-True ($null -eq $reading.value -and $null -ne $reading.missing_reason) 'Missing/invalid metric became a measured number'
}
$zero = New-Reading cpu percent 0 -Maximum 100
Assert-True ($zero.value -eq 0 -and $null -eq $zero.missing_reason) 'A real measured zero must be retained'
Assert-True ((Get-UsedPercent 100 25) -eq 75) 'Used-space conversion'
foreach ($pair in @(@($null, 0), @(0, 0), @(100, $null), @(100, -1), @(100, 101))) {
    Assert-True ($null -eq (Get-UsedPercent $pair[0] $pair[1])) 'Bad capacity became a healthy zero'
}
Assert-True ((Get-CounterRate 100 150 0.5) -eq 100) 'Rate must use elapsed seconds'
Assert-True ($null -eq (Get-CounterRate 150 100 1)) 'Counter reset must not yield a negative rate'
Assert-True ($null -eq (Get-CounterRate 100 150 0)) 'Zero interval must be unavailable'

# Mock only the fixed read-only provider seam; exercise the real wrappers.
$script:mode = 'denied'
function Get-CimInstance {
    param($ClassName, $Namespace, $Property, $Filter, $OperationTimeoutSec, $ErrorAction)
    switch ($script:mode) {
        denied { throw [UnauthorizedAccessException]::new('PRIVATE_IDENTIFIER_MUST_NOT_LEAK') }
        absent { return }
        nullBattery { return [pscustomobject]@{ EstimatedChargeRemaining = $null } }
        badDisk { return [pscustomobject]@{ Size = 100; FreeSpace = 101 } }
        thermal { return [pscustomobject]@{ CurrentTemperature = 3000 } }
    }
}
$denied = Get-WindowsProbeResult thermal
Assert-True ($denied.failure_reason -eq 'permission_denied') 'Permission denial must be distinct'
Assert-True (($denied | ConvertTo-Json -Depth 8) -notmatch 'PRIVATE_IDENTIFIER') 'Raw provider error leaked'
$script:mode = 'absent'
$absent = Get-WindowsProbeResult battery
Assert-True ($absent.readings[0].missing_reason -eq 'not_applicable') 'Absent battery is not a measured zero'
$script:mode = 'nullBattery'
$battery = Get-WindowsProbeResult battery
Assert-True ($null -eq $battery.readings[0].value) 'Null battery reading became zero'
$script:mode = 'badDisk'
$disk = Get-WindowsProbeResult disk
Assert-True ($disk.readings[0].missing_reason -eq 'collection_error') 'Invalid disk capacity must be explicit'
$script:mode = 'thermal'
$thermal = Get-WindowsProbeResult thermal
Assert-True ([math]::Abs($thermal.readings[0].value - 26.85) -lt 0.001) 'Thermal units must be tenths Kelvin to Celsius'
Remove-Item Function:\Get-CimInstance

$rejected = $false
try { Get-WindowsProbeResult 'cpu; arbitrary-command' } catch { $rejected = $true }
Assert-True $rejected 'Unknown/command-like sources must be rejected'
if ($IsWindows) {
    $timeout = Invoke-IsolatedProbe -Source network -TimeoutMilliseconds 1
    Assert-True ($timeout.failure_reason -eq 'timeout') 'Hung worker must be terminated with explicit timeout'
    $after = Invoke-IsolatedProbe -Source battery
    Assert-True ($after.ContainsKey('provider')) 'A timeout must not prevent a later source from running'
}
Write-Host "PASS: $checks Windows probe checks"
