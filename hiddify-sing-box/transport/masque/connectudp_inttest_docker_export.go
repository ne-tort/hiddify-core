package masque

// Inttest docker-paced/burst localize runners (W-UDP-4 inttest MOVE).

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/transport/masque/connectudp"
	h2c "github.com/sagernet/sing-box/transport/masque/h2"
	M "github.com/sagernet/sing/common/metadata"
)

// InttestGATEConnectUDPDockerSenderPacedParity locks in-proc sequenced sender vs docker udp_masque_send.py @8 Mbit/s (UDP-5b2).
func InttestGATEConnectUDPDockerSenderPacedParity(t *testing.T) {
	t.Helper()
	InttestLocalizeConnectUDPDockerPacedCompensatedPacing(t)
}

// InttestLocalizeConnectUDPDockerPacedDirectVsSocks5 localizes docker connect-udp-h3 paced path.
func InttestLocalizeConnectUDPDockerPacedDirectVsSocks5(t *testing.T) {
	t.Helper()
	const duration = connectUDPSynthProdBenchDuration
	target := dockerBenchUDPTargetMbit

	direct := benchConnectUDPPacedSinkGoodput(t, false, duration, target)
	socks := benchConnectUDPPacedSinkGoodput(t, true, duration, target)

	assertConnectUDPProbeLoss(t, "direct paced", direct.stats, connectUDPSynthMaxLossPct)
	assertConnectUDPProbeLoss(t, "socks paced", socks.stats, connectUDPSynthMaxLossPct)

	minFloor := connectudp.MinPacedGoodputMbit(target)
	if direct.mbps < minFloor {
		t.Fatalf("direct paced sink goodput %.2f Mbit/s < docker floor %.2f", direct.mbps, minFloor)
	}
	if socks.mbps < minFloor {
		t.Fatalf("socks paced sink goodput %.2f Mbit/s < docker floor %.2f", socks.mbps, minFloor)
	}

	ratio := socks.mbps / direct.mbps
	t.Logf("docker paced localize: direct=%.2f socks=%.2f Mbit/s ratio=%.2f (target %.0f floor %.2f)",
		direct.mbps, socks.mbps, ratio, target, minFloor)

	const maxSocksOverheadRatio = 1.12
	if ratio < 1.0/maxSocksOverheadRatio || ratio > maxSocksOverheadRatio {
		t.Fatalf("socks/direct paced ratio %.2f outside [%.2f, %.2f] — SOCKS path is the docker gap",
			ratio, 1.0/maxSocksOverheadRatio, maxSocksOverheadRatio)
	}
}

// InttestLocalizeConnectUDPDockerPacedCompensatedPacing verifies compensated pacing hits docker KPI band in-proc.
func InttestLocalizeConnectUDPDockerPacedCompensatedPacing(t *testing.T) {
	t.Helper()
	const duration = connectUDPSynthProdBenchDuration
	got := benchConnectUDPPacedSinkGoodput(t, false, duration, dockerBenchUDPTargetMbit)
	assertConnectUDPProbeLoss(t, "compensated paced", got.stats, connectUDPSynthMaxLossPct)

	if got.mbps < connectUDPLegacyPacedMinMbps || got.mbps > connectUDPLegacyPacedMaxMbps {
		t.Fatalf("compensated paced goodput %.2f Mbit/s (want %.1f–%.1f @ target %.0f)",
			got.mbps, connectUDPLegacyPacedMinMbps, connectUDPLegacyPacedMaxMbps, dockerBenchUDPTargetMbit)
	}
	t.Logf("compensated paced goodput: %.2f Mbit/s sent=%d rx=%d loss=%.2f%%",
		got.mbps, got.sentPkts, got.stats.RxPkts, got.stats.LossPct)
}

// InttestLocalizeConnectUDPDockerPacedH2UploadGoodput verifies H2 CONNECT-UDP upload meets docker paced floor in-proc.
func InttestLocalizeConnectUDPDockerPacedH2UploadGoodput(t *testing.T) {
	t.Helper()
	const duration = connectUDPSynthProdBenchDuration
	target := dockerBenchUDPTargetMbit

	sinkConn, seqSink := runUDPSequencedSink(t, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0}, 0xD0C0BEEF)
	sinkAddr := sinkConn.LocalAddr().(*net.UDPAddr)
	proxyPort := startInProcessH2UDPConnectProxy(t)
	session := startConnectUDPH2MasqueSession(t, proxyPort)

	waitCtx, cancel := context.WithTimeout(context.Background(), duration+connectUDPSynthGateWaitCtx)
	t.Cleanup(cancel)
	pkt, err := session.ListenPacket(waitCtx, M.Socksaddr{
		Addr: netip.MustParseAddr(sinkAddr.IP.String()),
		Port: uint16(sinkAddr.Port),
	})
	if err != nil {
		t.Fatalf("ListenPacket h2: %v", err)
	}
	t.Cleanup(func() { _ = pkt.Close() })

	got := benchConnectUDPPacedSinkGoodputWithPacket(t, pkt, sinkAddr, seqSink, 0xD0C0BEEF, duration, target)
	assertConnectUDPProbeLoss(t, "h2 paced upload", got.stats, connectUDPSynthMaxLossPct)
	minFloor := connectudp.MinPacedGoodputMbit(target)
	if got.mbps < minFloor {
		t.Fatalf("h2 paced upload goodput %.2f Mbit/s < docker floor %.2f", got.mbps, minFloor)
	}
	t.Logf("docker paced h2 upload: %.2f Mbit/s sent=%d rx=%d loss=%.2f%% (floor %.2f)",
		got.mbps, got.sentPkts, got.stats.RxPkts, got.stats.LossPct, minFloor)
}

// InttestLocalizeConnectUDPDockerPacedH3At500Socks: in-proc H3 SOCKS @500 must not overflow
// http3 stream_datagram_queue (F7.1 hard break was ≥500 with FlushChunk=1).
func InttestLocalizeConnectUDPDockerPacedH3At500Socks(t *testing.T) {
	t.Helper()
	localizeConnectUDPH3PacedQueueDropGuard(t, 500.0, 1.0)
}

// InttestLocalizeConnectUDPH3Paced600SocksQueueDropGuard same at 600 (post-fix drain target).
func InttestLocalizeConnectUDPH3Paced600SocksQueueDropGuard(t *testing.T) {
	t.Helper()
	localizeConnectUDPH3PacedQueueDropGuard(t, 600.0, 2.0)
}

func localizeConnectUDPH3PacedQueueDropGuard(t *testing.T, target, maxLossPct float64) {
	t.Helper()
	beforeQ := http3.StreamDatagramQueueDropTotal()
	beforeRcv := quic.DatagramReceiveQueueDropTotal()
	socks := benchConnectUDPPacedSinkGoodput(t, true, connectUDPSynthProdBenchDuration, target)
	deltaQ := http3.StreamDatagramQueueDropTotal() - beforeQ
	deltaRcv := quic.DatagramReceiveQueueDropTotal() - beforeRcv
	t.Logf("RESULT_H3_PACED_QUEUE_GUARD target=%.0f goodput=%.2f loss=%.3f%% rx=%d/%d stream_dgram_queue_drops_delta=%d quic_rcv_queue_drops_delta=%d",
		target, socks.mbps, socks.stats.LossPct, socks.stats.RxPkts, socks.sentPkts, deltaQ, deltaRcv)
	assertConnectUDPProbeLoss(t, "h3 socks paced queue-guard", socks.stats, maxLossPct)
	if deltaQ > 0 {
		t.Fatalf("h3 @%.0f stream_datagram_queue_drops delta=%d — C2S drain too slow (FlushChunk/WriteBatch)", target, deltaQ)
	}
	if deltaRcv > 0 {
		t.Fatalf("h3 @%.0f quic datagram_rcv_queue_drops delta=%d", target, deltaRcv)
	}
	minFloor := connectudp.MinPacedGoodputMbit(target) * 0.85
	if socks.mbps < minFloor {
		t.Fatalf("h3 socks @%.0f goodput %.2f < floor %.2f", target, socks.mbps, minFloor)
	}
}

// InttestLocalizeConnectUDPDockerPacedH2DirectVsSocks5 localizes docker connect-udp-h2 @500 Mbit/s paced KPI.
func InttestLocalizeConnectUDPDockerPacedH2DirectVsSocks5(t *testing.T) {
	t.Helper()
	t.Skip("in-proc SOCKS associate relay is not prod-shaped @500; use TestEndpointConnectUDPH2SocksBurstProdLaunchStack + docker _probe_profile")
	t.Setenv("MASQUE_H2_CONNECT_UDP_UPLOAD_STREAMS", "4")
	const duration = connectUDPSynthProdBenchDuration
	const target = 500.0

	direct := benchConnectUDPH2PacedSinkGoodput(t, false, duration, target)
	socks := benchConnectUDPH2PacedSinkGoodput(t, true, duration, target)

	assertConnectUDPProbeLoss(t, "h2 direct paced 500", direct.stats, connectUDPSynthMaxLossPct)
	assertConnectUDPProbeLoss(t, "h2 socks paced 500", socks.stats, connectUDPSynthMaxLossPct)

	minFloor := connectudp.MinPacedGoodputMbit(target)
	if direct.mbps < minFloor {
		t.Fatalf("h2 direct paced %.2f Mbit/s < floor %.2f", direct.mbps, minFloor)
	}
	if socks.mbps < minFloor {
		t.Fatalf("h2 socks paced %.2f Mbit/s < floor %.2f (direct=%.2f)", socks.mbps, minFloor, direct.mbps)
	}

	ratio := socks.mbps / direct.mbps
	t.Logf("docker paced h2 @500: direct=%.2f socks=%.2f Mbit/s ratio=%.2f loss=%.2f%%/%.2f%%",
		direct.mbps, socks.mbps, ratio, direct.stats.LossPct, socks.stats.LossPct)

	const maxSocksOverheadRatio = 1.05
	if ratio < 1.0/maxSocksOverheadRatio {
		t.Fatalf("h2 socks/direct paced ratio %.2f < %.2f — SOCKS relay gap", ratio, 1.0/maxSocksOverheadRatio)
	}
}

// InttestLocalizeConnectUDPH2BurstWritePacketVsWriteTo localizes relay WritePacket vs direct WriteTo.
func InttestLocalizeConnectUDPH2BurstWritePacketVsWriteTo(t *testing.T) {
	t.Helper()
	skipUnlessMasqueBenchLong(t)
	const duration = connectUDPSynthProdBenchDuration
	writeToMbps, _ := benchConnectUDPBurstZeroLossMax(t, option.MasqueHTTPLayerH2, false, duration)
	writePktMbps, _ := benchConnectUDPH2BurstZeroLossMaxWritePacket(t, duration)
	socksMbps, _ := benchConnectUDPBurstZeroLossMax(t, option.MasqueHTTPLayerH2, true, duration)
	t.Logf("h2 burst: WriteTo=%.1f WritePacket=%.1f SOCKS=%.1f Mbit/s", writeToMbps, writePktMbps, socksMbps)
	if writePktMbps < 400 && writeToMbps >= 450 {
		t.Fatalf("WritePacket relay entry %.1f << WriteTo %.1f — localize SOCKS relay shape before TCP",
			writePktMbps, writeToMbps)
	}
	if socksMbps < 400 && writePktMbps >= 450 {
		t.Fatalf("SOCKS UDP relay caps burst %.1f while WritePacket path %.1f — H2 HTTP/2 relay coupling (not SOCKS TCP)",
			socksMbps, writePktMbps)
	}
	if writePktMbps < 400 && writeToMbps >= 450 {
		t.Fatalf("WritePacket relay entry %.1f << WriteTo %.1f — bufio relay shape bottleneck",
			writePktMbps, writeToMbps)
	}
	t.Logf("OPEN: h2 burst socks=%.1f (need 500); writeTo=%.1f writePkt=%.1f", socksMbps, writeToMbps, writePktMbps)
}

// InttestLocalizeConnectUDPDockerBurstDirectVsSocks5 localizes max zero-loss burst (docker burst KPI shape).
func InttestLocalizeConnectUDPDockerBurstDirectVsSocks5(t *testing.T) {
	t.Helper()
	skipUnlessMasqueBenchLong(t)
	const duration = connectUDPSynthProdBenchDuration

	directMbps, directSt := benchConnectUDPBurstZeroLossMax(t, option.MasqueHTTPLayerH3, false, duration)
	socksMbps, socksSt := benchConnectUDPBurstZeroLossMax(t, option.MasqueHTTPLayerH3, true, duration)

	t.Logf("docker burst zero-loss h3: direct=%.1f socks=%.1f Mbit/s (rx %d/%d vs %d/%d)",
		directMbps, socksMbps, directSt.RxPkts, directSt.SentPkts, socksSt.RxPkts, socksSt.SentPkts)

	if !directSt.BurstZeroLossOK(connectudp.DefaultBenchUDPPayloadLen, connectudp.DefaultBurstMinRxRatio) {
		t.Fatalf("direct burst best probe failed zero-loss gate: %+v", directSt)
	}
	if !socksSt.BurstZeroLossOK(connectudp.DefaultBenchUDPPayloadLen, connectudp.DefaultBurstMinRxRatio) {
		t.Fatalf("socks burst best probe failed zero-loss gate: %+v", socksSt)
	}

	if directMbps < 80 {
		t.Fatalf("direct max zero-loss burst %.1f < 80 Mbit/s", directMbps)
	}
	if socksMbps < 80 {
		t.Fatalf("socks max zero-loss burst %.1f < 80 Mbit/s", socksMbps)
	}
	ratio := socksMbps / directMbps
	const minBurstSocksDirectRatio = 0.40
	if ratio < minBurstSocksDirectRatio {
		t.Fatalf("socks/direct burst zero-loss ratio %.2f < %.2f — SOCKS burst regression",
			ratio, minBurstSocksDirectRatio)
	}
	if ratio < 0.85 {
		t.Logf("NOTE: burst SOCKS overhead ~%.0f%% of direct (paced guard is ~1.0); optimize SOCKS/dataplane toward 0.85",
			ratio*100)
	}
}

// InttestLocalizeConnectUDPDockerBurstH2DirectVsSocks5 localizes H2 max zero-loss burst.
func InttestLocalizeConnectUDPDockerBurstH2DirectVsSocks5(t *testing.T) {
	t.Helper()
	skipUnlessMasqueBenchLong(t)
	const duration = connectUDPSynthProdBenchDuration

	directMbps, directSt := benchConnectUDPBurstZeroLossMax(t, option.MasqueHTTPLayerH2, false, duration)
	socksMbps, socksSt := benchConnectUDPBurstZeroLossMax(t, option.MasqueHTTPLayerH2, true, duration)

	t.Logf("docker burst zero-loss h2: direct=%.1f socks=%.1f Mbit/s (rx %d/%d vs %d/%d)",
		directMbps, socksMbps, directSt.RxPkts, directSt.SentPkts, socksSt.RxPkts, socksSt.SentPkts)

	if !directSt.BurstZeroLossOK(connectudp.DefaultBenchUDPPayloadLen, connectudp.DefaultBurstMinRxRatio) {
		t.Fatalf("h2 direct burst best probe failed zero-loss gate: %+v", directSt)
	}
	if !socksSt.BurstZeroLossOK(connectudp.DefaultBenchUDPPayloadLen, connectudp.DefaultBurstMinRxRatio) {
		t.Fatalf("h2 socks burst best probe failed zero-loss gate: %+v", socksSt)
	}

	const minDockerBurstMbps = 500.0
	const burstGoodputEpsilon = 0.5
	if directMbps < minDockerBurstMbps-burstGoodputEpsilon {
		t.Fatalf("h2 direct max zero-loss burst %.1f < %.0f Mbit/s", directMbps, minDockerBurstMbps)
	}
	if socksMbps < minDockerBurstMbps-burstGoodputEpsilon {
		t.Fatalf("h2 socks max zero-loss burst %.1f < %.0f Mbit/s (Docker uses SOCKS5 ASSOCIATE; in-proc direct=%.1f)",
			socksMbps, minDockerBurstMbps, directMbps)
	}
	ratio := socksMbps / directMbps
	if ratio < 0.85 {
		t.Fatalf("h2 socks/direct burst ratio %.2f < 0.85", ratio)
	}
}

// InttestLocalizeConnectUDPH2BurstDockerTlsTaxSweep calibrates tlsFlushTaxH2Link on burst shape.
func InttestLocalizeConnectUDPH2BurstDockerTlsTaxSweep(t *testing.T) {
	t.Helper()
	skipUnlessMasqueBenchLong(t)
	const duration = connectUDPSynthProdBenchDuration
	maxPayload := h2c.MaxUDPPayloadPerDatagramCapsule()

	instant512, _ := benchConnectUDPH2BurstZeroLossMax(t, instantH2Link{}, false, duration, connectudp.DefaultBenchUDPPayloadLen)
	instantMax, _ := benchConnectUDPH2BurstZeroLossMax(t, instantH2Link{}, false, duration, maxPayload)
	t.Logf("LOCALIZE h2 burst instant: 512B=%.1f maxCapsule(%dB)=%.1f (docker ~187 / ~374)", instant512, maxPayload, instantMax)

	for _, taxUs := range []int{4, 8, 12, 16, 20, 24, 32, 40, 48} {
		link := tlsFlushTaxH2Link{Tax: time.Duration(taxUs) * time.Microsecond}
		mbps512, _ := benchConnectUDPH2BurstZeroLossMax(t, link, false, duration, connectudp.DefaultBenchUDPPayloadLen)
		mbpsMax, _ := benchConnectUDPH2BurstZeroLossMax(t, link, false, duration, maxPayload)
		t.Logf("LOCALIZE h2 burst tls-tax=%dus/4KiB: 512B=%.1f maxCapsule=%.1f", taxUs, mbps512, mbpsMax)
	}
}

