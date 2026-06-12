# Run MASQUE layer gates from AGENTS.md / docs/masque/layers/50-testing.md (PR smoke).
# Clears cross-build GOOS/GOARCH like go-test-masque.ps1.
$ErrorActionPreference = "Stop"
$coreRoot = Split-Path $PSScriptRoot -Parent
$singbox = Join-Path $coreRoot "hiddify-sing-box"
if (-not (Test-Path $singbox)) {
    Write-Error "Expected hiddify-sing-box at: $singbox"
    exit 1
}

function Invoke-MasqueGate {
    param(
        [string]$Name,
        [string[]]$GoArgs
    )
    Write-Host "==> $Name" -ForegroundColor Cyan
    & go @GoArgs
    if ($LASTEXITCODE -ne 0) {
        Write-Error "gate failed: $Name (exit $LASTEXITCODE)"
        exit $LASTEXITCODE
    }
}

Push-Location $singbox
try {
    Remove-Item Env:GOOS -ErrorAction SilentlyContinue
    Remove-Item Env:GOARCH -ErrorAction SilentlyContinue

    Invoke-MasqueGate "L0 transport" @(
        "test", "./transport/masque/",
        "-run", "CoreSession|ResetHop|ClassifyError|HTTPLayerSwitchable|ConnectAuthority|ValidateQUICTransportPacketConn|QuicDialWithPolicy|ApplyQUICExperimental|QUICConfigForDial|WarpConnectStreamBearerToken|ClientTLS|OverlayFallback|DirectFallback|DirectSession|DialDirectTCP|OpenH3ClientConn",
        "-count=1", "-timeout", "90s"
    )
    Invoke-MasqueGate "L0 session" @(
        "test", "./transport/masque/session/",
        "-run", "OverlayCapability",
        "-count=1", "-timeout", "30s"
    )
    Invoke-MasqueGate "L1a H2" @(
        "test", "./transport/masque/",
        "-run", "H2Connect",
        "-count=1", "-timeout", "60s"
    )
    Invoke-MasqueGate "L1b H3" @(
        "test", "./transport/masque/",
        "-run", "H3Connect|DialTCPStreamHTTP3|DialTCPStreamInProcessHTTP3|H3QUIC",
        "-count=1", "-timeout", "90s"
    )
    Invoke-MasqueGate "L2 stream" @(
        "test", "./transport/masque/",
        "-run", "ConnectTunnel|ConnectStream|Relay|DialTCPStreamInProcess|DialWithHopChain|StreamDialHTTP3|StreamDialHTTP2|StreamDialAttempt|H3Tunnel|H2ConnectStreamUploadRepro",
        "-count=1", "-timeout", "120s"
    )
    Invoke-MasqueGate "L3 connect-ip" @(
        "test", "./transport/masque/",
        "-run", "ConnectIP|Localize",
        "-count=1", "-timeout", "90s"
    )
    Invoke-MasqueGate "L4 connect-udp" @(
        "test", "./transport/masque/",
        "-run", "ConnectIPUDP|ListenPacket|BuildAndParseIPv4UDP|H2ConnectUDP|ConnectUDPLocalize|DatagramSplit|DialH2|WarpH2|H2DialHost",
        "-count=1", "-timeout", "45s"
    )
    Invoke-MasqueGate "L4 connectudp pkg" @(
        "test", "./transport/masque/connectudp/",
        "-run", "ServeH2|H2Connect|DatagramSplit",
        "-count=1", "-timeout", "30s"
    )
    Invoke-MasqueGate "L5 protocol/masque" @(
        "test", "./protocol/masque/",
        "-count=1", "-timeout", "45s"
    )
    Invoke-MasqueGate "build with_masque (masque packages)" @(
        "build", "-tags", "with_masque",
        "./transport/masque/...", "./protocol/masque/..."
    )

    Write-Host "All MASQUE layer gates passed." -ForegroundColor Green
    exit 0
}
finally {
    Pop-Location
}
