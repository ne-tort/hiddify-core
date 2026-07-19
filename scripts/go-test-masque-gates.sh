#!/usr/bin/env bash
# Run MASQUE layer gates from AGENTS.md / docs/masque/layers/50-testing.md (PR smoke).
# Linux/CI mirror of go-test-masque-gates.ps1.
set -euo pipefail

core_root="$(cd "$(dirname "$0")/.." && pwd)"
singbox="${core_root}/hiddify-sing-box"

if [[ ! -d "${singbox}" ]]; then
  echo "Expected hiddify-sing-box at: ${singbox}" >&2
  exit 1
fi

invoke_masque_gate() {
  local name="$1"
  shift
  echo "==> ${name}"
  local output exit_code=0
  output="$(go "$@" 2>&1)" || exit_code=$?
  echo "${output}"
  if [[ ${exit_code} -ne 0 ]]; then
    echo "gate failed: ${name} (exit ${exit_code})" >&2
    exit "${exit_code}"
  fi
  if echo "${output}" | grep -q '\[no tests to run\]'; then
    echo "gate matched zero tests: ${name} (check -run pattern)" >&2
    exit 1
  fi
}

cd "${singbox}"
unset GOOS GOARCH 2>/dev/null || true

invoke_masque_gate "L0 runtime dial shape" test ./common/masque/ \
  -run 'RuntimeConnectStreamDialShape|RuntimeConnectStreamDialP8Floor|EndpointRuntimeSessionDownloadWriteToChain' \
  -count=1 -timeout 90s

invoke_masque_gate "L0 transport" test ./transport/masque/ \
  -run 'CoreSession|ResetHop|ClassifyError|HTTPLayerSwitchable|ConnectAuthority|ValidateQUICTransportPacketConn|QuicDialWithPolicy|ApplyQUICExperimental|QUICConfigForDial|WarpConnectStreamBearerToken|ClientTLS|OverlayFallback|DirectFallback|DirectSession|DialDirectTCP|OpenH3ClientConn|HTTPFallbackLatch|DispatchExit|ConnectStreamProdDialShape|DialTCPStreamHTTP3ReturnsTunnelConnShape|HTTPLayerFallbackConnectStreamWriteToParity|L0SessionGatePattern' \
  -count=1 -timeout 90s

invoke_masque_gate "L0 session" test ./transport/masque/session/ \
  -run 'OverlayCapability|EnsureTCPHTTPTransport|NewTCPConnectStreamHTTP3|P8FloorAfterExperimental|FinalizeRestoresBulkFC|HTTPFallbackLatch|DispatchExit|OverlayFallback|TeardownOverlay' \
  -count=1 -timeout 30s

invoke_masque_gate "L1a H2 masque" test ./transport/masque/ \
  -run 'H2Connect|ConnectIPIngressAckWakeH2' \
  -count=1 -timeout 60s

invoke_masque_gate "L1a H2 pkg" test ./transport/masque/h2/ \
  -run 'H2Connect|UploadFlush|ParseCapsule|BulkHTTP|FlushConnectIPIngressAckWake|FlushRequestBody|WriteAll|PerCapsuleFlush|TerminalFlush|NoFlush' \
  -count=1 -timeout 60s

invoke_masque_gate "L1b H3 (S53)" test ./transport/masque/ ./transport/masque/h3/ \
  -run 'H3Connect|DialTCPStreamHTTP3|DialTCPStreamInProcessHTTP3|H3QUIC|BidiDuplex|DuplexCoord|InterleaveDuplex|MasqueInterleaveDuplexTransferCPUBudget|MasqueH3Duplex|WrapBidiWindow|WrapBidiWindowWriteTo|SetBidiDownloadActiveOnRealQUIC|CloseWithPendingDuplexUpload|QuicConnectUploadChunkParity|EnqueueDuplexUploadBackpressure|DuplexDownloadActiveFramerBoostLink|MasqueH3WriteToDuplexVsCopyBufferParity|H3DuplexConnWakeReceiveVsDeliveryEnvMatrix|BidiUploadWakeDuringDownload|TunnelConnWakeBidiSend|ConnectStreamCPUBudgetWriteTo|L1bSynthGatePattern|ArchDuplexCoord' \
  -count=1 -timeout 90s

invoke_masque_gate "L1c quic patches" test -C ./replace/quic-go-patched . ./http3/ ./internal/flowcontrol/ \
  -run 'MasqueWake|MasqueWakeOncePerStreamRead|MasqueStreamWriteToReadChunk|FramerBidi|FramerAppendBidi|MasqueFramerAppendBidiContentionCPUBudget|MasqueFastWindow|MasqueDuplex|BidiSendBoost|ScheduleSendingCoalesce|Handle0RTTRejectionClears|AppendSkipsOrphan|LateActivation|SetBidiSendBoostTriggers|SimnetKPIBand|SimnetWriteTo|SimnetStreamReadWake|MasqueWakeAfterDownloadRead|DuplexSimnetBoostAB' \
  -count=1 -timeout 60s

invoke_masque_gate "L2 stream" test ./transport/masque/ \
  -run 'ConnectTunnel|ConnectStream|Relay|DialTCPStreamInProcess|DialWithHopChain|StreamDialHTTP3|StreamDialHTTP2|StreamDialAttempt|H3Tunnel|H2ConnectStream|RelayTunnelDownload|RelayTCPTunnelH3Hijack|RelayTunnelPrimeDownloadIperfBanner|RelayEnvMatrixDownload' \
  -count=1 -timeout 120s

invoke_masque_gate "L2 synth anchor" test ./transport/masque/ \
  -run 'BenchCeiling|BypassMatrix|ConnectStreamLocalizeDownloadWriteTo|ConnectStreamDuplexWriteTo|ConnectStreamParallelStreams|WindowedBidiBridge|MeasureTCPDownloadWriteTo|MeasureTCPDownloadMbpsAntiPattern|ReadPathSkipsDownloadActive|MeasureTCPDownloadCopy|ConnectStreamLocalizeBottleneck|ConnectStreamH2Localize|H2InstantDownload|H2ConnectStreamTCPUploadServerBanner|InstantDownloadExceedsVPSKPI|H2LocalizeDuplex|L256Window|SharedWindowedBidiHarnessDedupe|ForwarderDownloadWindowed|HarnessDownloadCopy|SimnetWindowedHarnessParity|ConnectStreamDownloadLayer|ConnectStreamCPUBudget|WindowedBidiConnThroughput|UploadL2WideWindowBand|PprofSymbol|RelayTCPTunnelDownloadPaths|ConnectStreamH2EndToEndDownload|NightlyCpuprofileWriteTo|L2SynthGatePattern|PerfLocalizeGatePattern|TestArch|ArchP1ProdDefault|ArchP2|ArchA4P8|ArchA4Acceptance' \
  -count=1 -timeout 120s

invoke_masque_gate "L2 stream pkg relay (S82)" test ./transport/masque/stream/ \
  -run 'BidiTunnel|H2Bidi|H2BidiDownloadDrain|DownloadPathAdapterSerializes|RelayTunnelPrimeDownloadBanner|RelayTunnelPrimeBannerFlushesEarly|RelayTunnelSelectUploadEOFUnblocksDownload|TunnelPaths|ServerRelayTwoGoroutineCPUBudget|ConnectStreamProdDialShape' \
  -count=1 -timeout 60s

invoke_masque_gate "L2 relay env (S54)" test ./transport/masque/stream/ ./protocol/masque/relay/ \
  -run 'MasqueRelayEnvMatrix|RelayUploadFromStreamEnv|RelayUseHTTP3StreamHijackEnv|UseLegacyFlushRelay|RelayTCPForwardWireContract|TCPBidirectional' \
  -count=1 -timeout 30s

invoke_masque_gate "L3 connect-ip" test ./transport/masque/ \
  -run 'ConnectIP|Localize' \
  -count=1 -timeout 90s

# P2-16 / F5-T8: vendor must compile and test without parent module (GOWORK=off skips integration/).
echo "==> L3 connect-ip-go no parent import"
bad_imports="$(GOWORK=off go list -C ./third_party/connect-ip-go -f '{{range .Imports}}{{println .}}{{end}}' . | grep -E 'sagernet/sing-box|/pathbuild' || true)"
if [[ -n "${bad_imports}" ]]; then
  echo "vendor reverse-import of parent/pathbuild:" >&2
  echo "${bad_imports}" >&2
  exit 1
fi
GOWORK=off invoke_masque_gate "L3 connect-ip-go vendor standalone" test -C ./third_party/connect-ip-go . \
  -count=1 -timeout 60s

invoke_masque_gate "L4 connect-udp" test ./transport/masque/ \
  -run 'ConnectIPUDP|ListenPacket|BuildAndParseIPv4UDP|H2ConnectUDP|ConnectUDPLocalize|Socks5' \
  -count=1 -timeout 45s

invoke_masque_gate "L4 connectudp pkg" test ./transport/masque/connectudp/ \
  -run 'ServeH2|H2Connect|H2PacketConn|DatagramSplit|ParseHTTP|PaceInterval|ZeroCorpus|UDPProbeFill' \
  -count=1 -timeout 30s

invoke_masque_gate "L5 protocol/masque" test ./protocol/masque/ \
  -count=1 -timeout 45s

invoke_masque_gate "L6 docker bench contract" test ./transport/masque/ \
  -run 'DockerBench|DocumentedEnvVars|DocSynthAnchor' \
  -count=1 -timeout 30s

invoke_masque_gate "L6 route copy" test ./route/ \
  -run 'ConnectionCopy|SelectConnectionCopyBranch|TraceCopyBranch|ConnectionManagerDownloadWriteTo|RouteStub|RouteConnectStream' \
  -count=1 -timeout 30s

invoke_masque_gate "build with_masque (masque packages)" build -tags with_masque \
  ./transport/masque/... ./protocol/masque/...

echo "All MASQUE layer gates passed."
