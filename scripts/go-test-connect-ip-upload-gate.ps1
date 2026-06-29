# GATE connect-ip upload synth — run on every fix wave. Docker only after exit 0.

$ErrorActionPreference = 'Stop'

$root = Split-Path -Parent $PSScriptRoot

Set-Location (Join-Path $root 'hiddify-sing-box')

Write-Host "=== connect-ip upload synth gate (phase 1: structural + regression) ===" -ForegroundColor Cyan

$phase1 = '^TestGATEConnectIPUploadSynth$|^TestGATEConnectIPUploadSynthNative$|^TestLocalizeConnectIPUploadDatagramWakeCoalescing$|^TestLocalizeConnectIPUploadNativeConcurrentDownloadPollution$|^TestLocalizeConnectIPUploadPipeClientPacketSession$|^TestLocalizeConnectIPUploadNativeObs$|^TestMasqueConnectIPLocalizeRecycle$'

go test ./transport/masque/ -run $phase1 -count=1 -timeout 180s -v

if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Host "=== forwarder unit (upload ACK path) ===" -ForegroundColor Cyan

go test ./transport/masque/forwarder/ -run 'TestForwarder' -count=1 -timeout 60s -v

if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Host "=== connectip egress unit ===" -ForegroundColor Cyan

go test ./transport/masque/connectip/ -run 'TestClientPacketSessionEgress|TestConnectIPOutbound|TestOutboundHeadroom|TestReclaim|TestBatchingPipe' -count=1 -timeout 60s -v

exit $LASTEXITCODE
