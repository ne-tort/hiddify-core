package masque

import (
	"net"
	"net/http"
	"testing"

	"github.com/sagernet/sing-box/transport/masque/connectudp"
)

const connectUDPH3ParallelAttributionStreams = 4

// localizeConnectUDPH3ParallelScalingAttribution compares intra-session xN vs N×CoreSession x1 upload.
// Localize only — attributes H3 multi-flow ceiling (QUIC mux vs server fan-out) without failing gate.
func localizeConnectUDPH3ParallelScalingAttribution(t *testing.T) {
	t.Helper()
	layer := "h3"
	streams := connectUDPH3ParallelAttributionStreams
	dur := connectUDPSynthProdBenchDuration
	payloadLen := connectudp.DefaultBenchUDPPayloadLen

	sink, _ := runUDPSink(t, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	sinkAddr := sink.LocalAddr().(*net.UDPAddr)
	proxyPort := startInProcessMasqueUDPProxy(t, func(mux *http.ServeMux, p int) {
		registerMasqueUDPProxyHandler(t, mux, p)
	})

	_, singlePer, _ := benchParallelConnectUDPStreams(t, layer, proxyPort, sinkAddr, 1, dur, payloadLen)
	intraAgg, intraPer, intraSym := benchParallelConnectUDPStreams(t, layer, proxyPort, sinkAddr, streams, dur, payloadLen)
	multiAgg, multiPer, multiSym := benchParallelConnectUDPMultiSession(t, layer, proxyPort, sinkAddr, streams, dur, payloadLen)

	intraSingle := 0.0
	if len(singlePer) > 0 {
		intraSingle = singlePer[0]
	}
	intraEff := 0.0
	if intraSingle > 0 {
		intraEff = intraAgg / (intraSingle * float64(streams))
	}
	multiRatio := 0.0
	if intraAgg > 0 {
		multiRatio = multiAgg / intraAgg
	}

	t.Logf("LOCALIZE h3 parallel attribution x%d:", streams)
	t.Logf("  single-stream baseline: %.1f Mbit/s", intraSingle)
	t.Logf("  intra-session: agg=%.1f eff=%.2f sym=%.2f per=[%s]",
		intraAgg, intraEff, intraSym, formatStreamMbps(intraPer, dur))
	t.Logf("  multi-session: agg=%.1f sym=%.2f per=[%s] multi/intra=%.2f",
		multiAgg, multiSym, formatStreamMbps(multiPer, dur), multiRatio)

	switch {
	case multiRatio >= 1.35:
		t.Logf("OPEN: multi-session >> intra-session — QUIC single-connection mux ceiling (ref: separate CoreSession per flow or Linux Docker parallel probe)")
	case multiRatio <= 1.10:
		t.Logf("OPEN: multi-session ~ intra-session — shared server/relay fan-out ceiling (ref: masque-go sync relay, not client mux)")
	default:
		t.Logf("OPEN: mixed attribution (multi/intra=%.2f) — profile on Linux Docker run_udp_parallel_* probe", multiRatio)
	}
}
