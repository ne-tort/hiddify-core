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
    $output = & go @GoArgs 2>&1 | Out-String
    Write-Host $output
    if ($LASTEXITCODE -ne 0) {
        Write-Error "gate failed: $Name (exit $LASTEXITCODE)"
        exit $LASTEXITCODE
    }
    if ($output -match '\[no tests to run\]') {
        Write-Error "gate matched zero tests: $Name (check -run pattern)"
        exit 1
    }
}

Push-Location $singbox
try {
    Remove-Item Env:GOOS -ErrorAction SilentlyContinue
    Remove-Item Env:GOARCH -ErrorAction SilentlyContinue

    Invoke-MasqueGate "L0 runtime dial shape" @(
        "test", "./common/masque/",
        "-run", "RuntimeConnectStreamDialShape|RuntimeConnectStreamDialP8Floor|EndpointRuntimeSessionDownloadWriteToChain",
        "-count=1", "-timeout", "90s"
    )
    Invoke-MasqueGate "L0 transport" @(
        "test", "./transport/masque/",
        "-run", "CoreSession|ResetHop|ClassifyError|HTTPLayerSwitchable|ValidateQUICTransportPacketConn|QuicDialWithPolicy|ApplyQUICExperimental|QUICConfigForDial|WarpConnectStreamBearerToken|ClientTLS|OverlayFallback|DirectFallback|DirectSession|DialDirectTCP|OpenH3ClientConn|HTTPFallbackLatch|DispatchExit|ConnectStreamProdDialShape|DialTCPStreamHTTP3ReturnsTunnelConnShape|HTTPLayerFallbackConnectStreamWriteToParity|L0SessionGatePattern|PostA3PatternGuard",
        "-count=1", "-timeout", "90s"
    )
    Invoke-MasqueGate "L0 session" @(
        "test", "./transport/masque/session/",
        "-run", "OverlayCapability|EnsureTCPHTTPTransport|NewTCPConnectStreamHTTP3|P8FloorAfterExperimental|FinalizeRestoresBulkFC|HTTPFallbackLatch|DispatchExit|OverlayFallback|TeardownOverlay",
        "-count=1", "-timeout", "30s"
    )
    Invoke-MasqueGate "L1a H2 masque" @(
        "test", "./transport/masque/",
        "-run", "H2Connect|ConnectIPIngressAckWakeH2",
        "-count=1", "-timeout", "60s"
    )
    Invoke-MasqueGate "L1a H2 pkg" @(
        "test", "./transport/masque/h2/",
        "-run", "H2Connect|UploadFlush|ParseCapsule|BulkHTTP|FlushConnectIPIngressAckWake|FlushRequestBody|WriteAll|PerCapsuleFlush|TerminalFlush|NoFlush",
        "-count=1", "-timeout", "60s"
    )
    Invoke-MasqueGate "L1b H3 (S53)" @(
        "test", "./transport/masque/", "./transport/masque/h3/",
        "-run", "H3Connect|DialTCPStreamHTTP3|DialTCPStreamInProcessHTTP3|H3QUIC|BidiDuplex|InterleaveDuplex|MasqueInterleaveDuplexTransferCPUBudget|MasqueH3Duplex|WrapBidiWindow|WrapBidiWindowWriteTo|SetBidiDownloadActiveOnRealQUIC|CloseDuringActiveDownload|QuicConnectUploadChunkParity|DuplexDownloadActiveFramerBoostLink|MasqueH3WriteToDownloadDrain|TunnelConnDuplexCoordEndToEnd|H3DuplexConnWakeReceiveVsDeliveryEnvMatrix|BidiUploadWakeDuringDownload|TunnelConnWakeBidiSend|ConnectStreamCPUBudgetWriteTo|L1bSynthGatePattern|TunnelConnDuplexCoord|MasqueH3DuplexWakeEnvMatrix",
        "-count=1", "-timeout", "90s"
    )
    Invoke-MasqueGate "L1c quic patches" @(
        "test", "-C", "./replace/quic-go-patched", ".", "./http3/", "./internal/flowcontrol/",
        "-run", "MasqueWake|MasqueWakeOncePerStreamRead|MasqueStreamWriteToReadChunk|FramerBidi|FramerAppendBidi|MasqueFramerAppendBidiContentionCPUBudget|MasqueFastWindow|MasqueDuplex|BidiSendBoost|ScheduleSendingCoalesce|Handle0RTTRejectionClears|AppendSkipsOrphan|LateActivation|SetBidiSendBoostTriggers|SimnetKPIBand|SimnetWriteTo|SimnetStreamReadWake|MasqueWakeAfterDownloadRead|DuplexSimnetBoostAB",
        "-count=1", "-timeout", "60s"
    )
    Invoke-MasqueGate "L2 stream" @(
        "test", "./transport/masque/",
        "-run", "ConnectTunnel|ConnectStream|Relay|DialTCPStreamInProcess|DialWithHopChain|StreamDialHTTP3|StreamDialHTTP2|StreamDialAttempt|H3Tunnel|H2ConnectStream|RelayTunnelDownload|RelayTCPTunnelH3Hijack|RelayTunnelPrimeDownloadIperfBanner|RelayEnvMatrixDownload",
        "-count=1", "-timeout", "120s"
    )
    Invoke-MasqueGate "L2 synth anchor" @(
        "test", "./transport/masque/",
        "-run", "BenchCeiling|BypassMatrix|ConnectStreamLocalizeDownloadWriteTo|ConnectStreamDuplexWriteTo|ConnectStreamParallelStreams|WindowedBidiBridge|MeasureTCPDownloadWriteTo|MeasureTCPDownloadMbpsAntiPattern|ReadPathSkipsDownloadActive|MeasureTCPDownloadCopy|ConnectStreamLocalizeBottleneck|ConnectStreamH2Localize|H2InstantDownload|H2ConnectStreamTCPUploadServerBanner|InstantDownloadExceedsVPSKPI|H2LocalizeDuplex|L256Window|SharedWindowedBidiHarnessDedupe|ForwarderDownloadWindowed|HarnessDownloadCopy|SimnetWindowedHarnessParity|ConnectStreamDownloadLayer|ConnectStreamCPUBudget|WindowedBidiConnThroughput|UploadL2WideWindowBand|PprofSymbol|RelayTCPTunnelDownloadPaths|ConnectStreamH2EndToEndDownload|NightlyCpuprofileWriteTo|L2SynthGatePattern|PerfLocalizeGatePattern|TestArch|ArchP1ProdDefault|ArchA4P8|ArchA4Acceptance|PostA3PatternGuard",
        "-count=1", "-timeout", "120s"
    )
    Invoke-MasqueGate "L2 stream pkg relay (S82)" @(
        "test", "./transport/masque/stream/",
        "-run", "BidiTunnel|H2Bidi|H2BidiDownloadDrain|DownloadPathAdapterSerializes|RelayTunnelPrimeDownloadBanner|RelayTunnelPrimeBannerFlushesEarly|RelayTunnelSelectUploadEOFUnblocksDownload|TunnelPaths|ServerRelayTwoGoroutineCPUBudget|ConnectStreamProdDialShape",
        "-count=1", "-timeout", "60s"
    )
    Invoke-MasqueGate "L2 relay env (S54)" @(
        "test", "./transport/masque/stream/", "./protocol/masque/relay/",
        "-run", "MasqueRelayEnvMatrix|RelayUploadFromStreamEnv|RelayUseHTTP3StreamHijackEnv|UseLegacyFlushRelay|RelayTCPForwardWireContract|TCPBidirectional",
        "-count=1", "-timeout", "30s"
    )
    Invoke-MasqueGate "L3 connect-ip" @(
        "test", "./transport/masque/",
        "-run", "ConnectIP|Localize|HybridConnectStream",
        "-count=1", "-timeout", "90s"
    )
    Invoke-MasqueGate "L4 connect-udp" @(
        "test", "./transport/masque/",
        "-run", "ConnectIPUDP|ListenPacket|BuildAndParseIPv4UDP|H2ConnectUDP|ConnectUDPLocalize|Socks5|ProdProfileCapsule",
        "-count=1", "-timeout", "45s"
    )
    Invoke-MasqueGate "L4 connectudp pkg" @(
        "test", "./transport/masque/connectudp/",
        "-run", "ServeH2|H2Connect|H2PacketConn|DatagramSplit|ParseHTTP|PaceInterval|ZeroCorpus|UDPProbeFill",
        "-count=1", "-timeout", "30s"
    )
    Invoke-MasqueGate "L5 protocol/masque" @(
        "test", "./protocol/masque/",
        "-count=1", "-timeout", "60s"
    )
    Invoke-MasqueGate "L6 docker bench contract" @(
        "test", "./transport/masque/",
        "-run", "DockerBench|DocumentedEnvVars|DocSynthAnchor|LegacyAuthority",
        "-count=1", "-timeout", "30s"
    )
    Invoke-MasqueGate "L6 route copy" @(
        "test", "./route/",
        "-run", "ConnectionCopy|SelectConnectionCopyBranch|TraceCopyBranch|ConnectionManagerDownloadWriteTo|RouteStub|RouteConnectStream",
        "-count=1", "-timeout", "30s"
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
