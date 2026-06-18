# GATE connect-ip upload synth — run on every fix wave. Docker only after exit 0.
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
Set-Location (Join-Path $root 'hiddify-sing-box')

$run = 'TestGATEConnectIPUploadSynth|TestGATEConnectIPUploadSynthNative|TestLocalizeConnectIPUploadNativeObs|TestLocalizeConnectIPUploadTUNEgressSerialWrite|TestMasqueConnectIPLocalizeBottleneck|TestConnectIPLocalizeForwarderWakeAndWriteQueueMetrics'
Write-Host "=== connect-ip upload synth gate ===" -ForegroundColor Cyan
go test ./transport/masque/ -run $run -count=1 -timeout 180s -v
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Host "=== forwarder unit (upload ACK path) ===" -ForegroundColor Cyan
go test ./transport/masque/forwarder/ -run 'TestForwarder' -count=1 -timeout 60s -v
exit $LASTEXITCODE
