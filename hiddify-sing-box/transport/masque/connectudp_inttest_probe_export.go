package masque

import (
	"net"
	"testing"

	"github.com/sagernet/sing-box/transport/masque/connectudp"
)

func InttestProbeConnectUDPScalingCeiling(t *testing.T) {
	if testing.Short() {
		t.Skip("scaling ceiling probe")
	}
	for _, layer := range []string{"h2", "h3"} {
		layer := layer
		t.Run(layer, func(t *testing.T) {
			probeConnectUDPScalingCeiling(t, layer, []int{1, 2, 4})
		})
	}
}

func InttestProbeConnectUDPIntraVsInterScaling(t *testing.T) {
	if testing.Short() {
		t.Skip("intra vs inter scaling probe")
	}
	const streams = 4
	dur := connectUDPSynthProdBenchDuration
	payloadLen := connectudp.DefaultBenchUDPPayloadLen
	sink, _ := runUDPSink(t, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	sinkAddr := sink.LocalAddr().(*net.UDPAddr)
	proxyPort := startInProcessH2UDPConnectProxy(t)

	interAgg, _, interSym := benchParallelConnectUDPStreams(t, "h2", proxyPort, sinkAddr, streams, dur, payloadLen)
	t.Logf("inter-flow N=%d: agg=%.1f sym=%.2f", streams, interAgg, interSym)

	t.Setenv("MASQUE_H2_CONNECT_UDP_UPLOAD_STREAMS", "4")
	intraAgg, intraPer, intraSym := benchIntraFlowH2UploadStreams(t, proxyPort, sinkAddr, streams, dur, payloadLen)
	t.Logf("intra-flow UPLOAD_STREAMS=%d: agg=%.1f sym=%.2f per=[%s]", streams, intraAgg, intraSym, formatStreamMbps(intraPer, dur))
}
