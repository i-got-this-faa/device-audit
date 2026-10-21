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
    Write-Host 'PASS: Windows vet/race/format/model checks, native fixture demo, cross-builds and probe checks'
} finally {
    foreach ($name in $saved.Keys) { [Environment]::SetEnvironmentVariable($name, $saved[$name], 'Process') }
    Pop-Location
}
