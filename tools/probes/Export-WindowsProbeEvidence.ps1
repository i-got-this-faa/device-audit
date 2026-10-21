#requires -Version 7.0
[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidateCount(1, 2)][string[]]$ReportPath,
    [Parameter(Mandatory)][string]$OutputPath
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
. "$PSScriptRoot/WindowsProbe.ps1"

# Reconstruct published text from the fixed catalog and validated numbers only.
# Never copy environment strings, instances, timestamps or raw errors from input.
$lines = [Collections.Generic.List[string]]::new()
$lines.Add('# Windows probe source availability')
$lines.Add('')
$lines.Add('Local development reports, not production qualification. Slots do not prove distinct physical machines. The operator must attest target identity privately and confirm two real selected machines before claiming #21 acceptance.')
$lines.Add('')
$sources = @('cpu', 'memory', 'disk', 'network', 'battery', 'thermal', 'gpu', 'events')
$reasons = @('sensor_unavailable', 'not_applicable', 'permission_denied', 'collection_error', 'timeout', 'worker_error')
for ($slot = 0; $slot -lt $ReportPath.Count; $slot++) {
    $file = Get-Item -LiteralPath $ReportPath[$slot]
    if ($file.Length -gt 8MB) { throw 'Report exceeds the 8 MiB evidence limit.' }
    $report = Get-Content -LiteralPath $file.FullName -Raw | ConvertFrom-Json -AsHashtable
    if ($report.schema_version -cne 'device-audit.windows-probe.v1' -or $report.provenance -cne 'real' -or
        $report.purpose -cne 'development_source_availability_and_probe_cost_only') {
        throw 'Only current real Windows probe reports are accepted; fixture and legacy reports are not reclassified.'
    }
    if ($report.sweeps.Count -lt 1 -or $report.sweeps.Count -gt 30) { throw 'Invalid sweep count.' }
    $lines.Add("## Target slot $($slot + 1)")
    $lines.Add('')
    $lines.Add('| Source | Metric | Provider | Unit | Observed range | Missing reasons |')
    $lines.Add('| --- | --- | --- | --- | --- | --- |')
    foreach ($source in $sources) {
        foreach ($metric in @(Get-ProbeMetricCatalog -Source $source)) {
            $values = [Collections.Generic.List[double]]::new()
            $missing = [Collections.Generic.List[string]]::new()
            foreach ($sweep in $report.sweeps) {
                $results = @($sweep.sources | Where-Object { $_.source -ceq $source })
                if ($results.Count -ne 1 -or $sweep.sources.Count -ne $sources.Count) { throw 'Missing or duplicate source.' }
                $result = $results[0]
                if ($result.provenance -cne 'real') { throw 'Fixture or unknown source provenance.' }
                $readings = @($result.readings | Where-Object { $_.name -ceq $metric.name })
                if ($readings.Count -lt 1 -or $readings.Count -gt 64) { throw 'Missing or excessive metric readings.' }
                foreach ($reading in $readings) {
                    if ($reading.unit -cne $metric.unit -or $reading.provider -cne $metric.provider -or $reading.provenance -cne 'real') {
                        throw 'Metric unit, provider or provenance mismatch.'
                    }
                    if ($null -eq $reading.value) {
                        if ($reading.missing_reason -cnotin $reasons) { throw 'Missing metric requires a known reason.' }
                        $missing.Add($reading.missing_reason)
                    } else {
                        if ($reading.value -is [string] -or $reading.value -is [bool] -or $null -ne $reading.missing_reason) { throw 'Invalid numeric reading.' }
                        $number = [double]$reading.value
                        if ([double]::IsNaN($number) -or [double]::IsInfinity($number) -or
                            ($metric.unit -eq 'percent' -and ($number -lt 0 -or $number -gt 100)) -or
                            ($metric.unit -eq 'boolean' -and $number -notin 0, 1) -or
                            ($metric.unit -eq 'celsius' -and $number -lt -273.15) -or
                            ($metric.unit -notin 'celsius', 'percent', 'boolean' -and $number -lt 0)) {
                            throw 'Numeric reading outside its unit bounds.'
                        }
                        $values.Add($number)
                    }
                }
            }
            $range = 'unavailable'
            if ($values.Count -gt 0) {
                $stats = $values | Measure-Object -Minimum -Maximum
                $range = $stats.Minimum.ToString('0.####', [Globalization.CultureInfo]::InvariantCulture) + ' to ' +
                    $stats.Maximum.ToString('0.####', [Globalization.CultureInfo]::InvariantCulture)
            }
            $reason = (@($missing | Sort-Object -Unique) -join ', ')
            if ($reason -eq '') { $reason = 'none' }
            $lines.Add("| $source | $($metric.name) | $($metric.provider) | $($metric.unit) | $range | $reason |")
        }
    }
    $lines.Add('')
}
$lines.Add('Ranges combine source-local instances across sweeps, not stable component identities or host totals. Missing is not zero or healthy. Recent error presence covers at most one critical/error event per selected provider in 24 hours; no match is not an error-free-device claim. This does not qualify ingestion or bookmarks. No Security log or event payload is included.')
$fullOutput = [IO.Path]::GetFullPath($OutputPath)
$stream = [IO.File]::Open($fullOutput, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write)
try {
    $bytes = [Text.Encoding]::UTF8.GetBytes(($lines -join "`n") + "`n")
    $stream.Write($bytes)
} finally { $stream.Dispose() }
Write-Host 'Saved minimized evidence. Review it before publication; no upload was performed.'
