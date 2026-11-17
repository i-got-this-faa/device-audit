#requires -Version 7.0
[CmdletBinding()]
param([string]$Python = 'python')
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
if (-not $IsWindows) { throw 'Use make check cross-build demo on non-Windows hosts.' }
if ([Runtime.InteropServices.RuntimeInformation]::OSArchitecture -ne [Runtime.InteropServices.Architecture]::X64) {
    throw 'This native validation command currently targets Windows x64.'
}
function Invoke-Checked([string]$Program, [string[]]$Arguments) {
    & $Program @Arguments
    if ($LASTEXITCODE -ne 0) { throw "$Program failed with exit code $LASTEXITCODE" }
}
$saved = @{}
foreach ($name in 'CGO_ENABLED', 'GOOS', 'GOARCH', 'PYTHONPATH') {
    $saved[$name] = [Environment]::GetEnvironmentVariable($name, 'Process')
}
Push-Location (Split-Path $PSScriptRoot)
try {
    # Fail explicitly if race prerequisites are absent; never silently skip it.
    $null = Get-Command go -ErrorAction Stop
    $null = Get-Command gcc -ErrorAction Stop
    $env:CGO_ENABLED = '1'
    $env:GOOS = 'windows'
    $env:GOARCH = 'amd64'
    Invoke-Checked go @('vet', './...')
    Invoke-Checked go @('test', '-race', './...')
    $formatted = & go fmt ./...
    if ($LASTEXITCODE -ne 0 -or $formatted) { throw 'Go formatting check failed; inspect the changed files.' }
    Invoke-Checked go @('run', './tools/fakes/controllerfake', '--scenario', 'all')
    $env:PYTHONPATH = 'models/src'
    Invoke-Checked $Python @('-m', 'unittest', 'discover', '-s', 'models/tests')
    $null = New-Item -ItemType Directory -Force -Path bin
    Invoke-Checked go @('build', '-o', 'bin/controller.exe', './apps/controller')
    Invoke-Checked go @('build', '-o', 'bin/endpoint-agent.exe', './apps/endpoint-agent')
    Invoke-Checked $Python @('tools/demo.py')
    $env:CGO_ENABLED = '0'
    Invoke-Checked go @('build', '-o', 'bin/endpoint-agent-windows.exe', './apps/endpoint-agent')
    $env:GOOS = 'darwin'
    $env:GOARCH = 'arm64'
    Invoke-Checked go @('build', '-o', 'bin/endpoint-agent-darwin', './apps/endpoint-agent')
    & "$PSScriptRoot/probes/Test-WindowsProbe.ps1"
    # The Darwin cross-build above changes GOOS. Restore the native Windows
    # toolchain before timing the synthetic sampler. This is not a physical
    # target or LocalService measurement.
    $env:CGO_ENABLED = '1'
    $env:GOOS = 'windows'
    $env:GOARCH = 'amd64'
    $null = New-Item -ItemType Directory -Force -Path artifacts/collector-budget
    Invoke-Checked go @('run', './tools/probes/collectorbudget',
        '-output', 'artifacts/collector-budget/windows-ci.json',
        '-interval', '15s', '-samples', '2', '-repeats', '1', '-baseline', '1s', '-iterations', '200000')
    # CPU, memory, disk, network, battery, thermal and GPU availability through
    # the Go collector (#91, #92).
    # A hosted VM under the CI account; not a physical target or LocalService token.
    $null = New-Item -ItemType Directory -Force -Path artifacts/sensors
    Invoke-Checked go @('run', './tools/probes/sensoravailability',
        '-output', 'artifacts/sensors/windows-ci.json', '-samples', '2', '-interval', '2s')
    Write-Host 'PASS: Windows vet/race/format/model checks, native fixture demo, cross-builds, probe checks, synthetic collector budget and sensor availability'
} finally {
    foreach ($name in $saved.Keys) { [Environment]::SetEnvironmentVariable($name, $saved[$name], 'Process') }
    Pop-Location
}
