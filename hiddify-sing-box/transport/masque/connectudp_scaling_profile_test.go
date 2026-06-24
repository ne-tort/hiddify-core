package masque

import (
	"context"
	"crypto/tls"
	"fmt"
	"math"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/transport/masque/connectudp"
	M "github.com/sagernet/sing/common/metadata"
)

// TestProbeConnectUDPScalingCeiling logs aggregate vs N and per-stream symmetry (diagnostic, not a hard gate).
func TestProbeConnectUDPScalingCeiling(t *testing.T) {
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

// TestProbeConnectUDPIntraVsInterScaling compares inter-flow (N ListenPacket) vs intra-flow (UPLOAD_STREAMS=N).
func TestProbeConnectUDPIntraVsInterScaling(t *testing.T) {
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

func benchIntraFlowH2UploadStreams(
	t *testing.T,
	proxyPort int,
	sinkAddr *net.UDPAddr,
	streams int,
	dur time.Duration,
	payloadLen int,
) (aggMbps float64, perStreamMbps []float64, symmetry float64) {
	t.Helper()
	session, waitCtx := newConnectUDPProdProfileH2SessionWithLink(t, proxyPort, instantH2Link{})
	defer func() { _ = session.Close() }()
	pkt, err := session.ListenPacket(waitCtx, M.Socksaddr{
		Addr: netip.MustParseAddr(sinkAddr.IP.String()),
		Port: uint16(sinkAddr.Port),
	})
	if err != nil {
		t.Fatalf("ListenPacket: %v", err)
	}
	defer func() { _ = pkt.Close() }()

	payload := make([]byte, payloadLen)
	t0 := time.Now()
	deadline := t0.Add(dur)
	var sent int64
	for time.Now().Before(deadline) {
		if err := writeToBenchUpload(pkt, payload, sinkAddr); err != nil {
			break
		}
		sent += int64(len(payload))
	}
	elapsed := time.Since(t0).Seconds()
	if elapsed < 0.1 {
		elapsed = 0.1
	}
	aggMbps = (float64(sent) * 8) / (elapsed * 1e6)
	// Intra-flow: one UDPFlow fans upload across N H2 upload legs — report aggregate only.
	perStreamMbps = []float64{aggMbps / float64(streams)}
	symmetry = 1.0
	return aggMbps, perStreamMbps, symmetry
}

func probeConnectUDPScalingCeiling(t *testing.T, layer string, streamCounts []int) {
	t.Helper()
	dur := connectUDPSynthProdBenchDuration
	payloadLen := connectudp.DefaultBenchUDPPayloadLen

	sink, _ := runUDPSink(t, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	sinkAddr := sink.LocalAddr().(*net.UDPAddr)

	var singleMbps float64
	switch layer {
	case "h2":
		_, singleMbps, _ = benchConnectUDPProdProfileH2Upload(t, instantH2Link{}, dur, 0, payloadLen)
	case "h3":
		_, singleMbps, _ = benchConnectUDPProdProfileH3Upload(t, instantDatagramLink{}, dur, 0, payloadLen)
	default:
		t.Fatalf("unknown layer %q", layer)
	}

	t.Logf("ceiling probe %s: single-stream baseline %.1f Mbit/s", layer, singleMbps)

	var proxyPort int
	switch layer {
	case "h2":
		proxyPort = startInProcessH2UDPConnectProxy(t)
	case "h3":
		proxyPort = startInProcessMasqueUDPProxy(t, func(mux *http.ServeMux, p int) {
			registerMasqueUDPProxyHandler(t, mux, p)
		})
	}

	for _, streams := range streamCounts {
		streams := streams
		agg, perStream, sym := benchParallelConnectUDPStreams(t, layer, proxyPort, sinkAddr, streams, dur, payloadLen)
		eff := 0.0
		if singleMbps > 0 {
			eff = agg / (singleMbps * float64(streams))
		}
		t.Logf("  N=%d: agg=%.1f Mbit/s eff=%.2f sym=%.2f per=[%s]",
			streams, agg, eff, sym, formatStreamMbps(perStream, dur))
	}
}

func benchParallelConnectUDPStreams(
	t *testing.T,
	layer string,
	proxyPort int,
	sinkAddr *net.UDPAddr,
	streams int,
	dur time.Duration,
	payloadLen int,
) (aggMbps float64, perStreamMbps []float64, symmetry float64) {
	t.Helper()

	waitCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	var session ClientSession
	switch layer {
	case "h2":
		session, waitCtx = newConnectUDPProdProfileH2SessionWithLink(t, proxyPort, instantH2Link{})
	case "h3":
		var err error
		session, err = (CoreClientFactory{}).NewSession(waitCtx, ClientOptions{
			Server:              "127.0.0.1",
			ServerPort:          uint16(proxyPort),
			TransportMode:       option.MasqueTransportModeConnectUDP,
			MasqueQUICCryptoTLS: &tls.Config{InsecureSkipVerify: true},
		})
		if err != nil {
			t.Fatalf("session: %v", err)
		}
	}
	defer func() { _ = session.Close() }()

	pkts := make([]net.PacketConn, streams)
	for i := 0; i < streams; i++ {
		pkt, lerr := session.ListenPacket(waitCtx, M.Socksaddr{
			Addr: netip.MustParseAddr(sinkAddr.IP.String()),
			Port: uint16(sinkAddr.Port),
		})
		if lerr != nil {
			t.Fatalf("ListenPacket %d: %v", i, lerr)
		}
		pkts[i] = pkt
	}
	defer func() {
		for _, p := range pkts {
			if p != nil {
				_ = p.Close()
			}
		}
	}()

	payload := make([]byte, payloadLen)
	perBytes := make([]atomic.Int64, streams)
	var wg sync.WaitGroup
	start := make(chan struct{})
	t0 := time.Now()
	deadline := t0.Add(dur)
	wg.Add(streams)
	for i := 0; i < streams; i++ {
		i := i
		pkt := pkts[i]
		go func() {
			defer wg.Done()
			<-start
			for time.Now().Before(deadline) {
				_ = pkt.SetWriteDeadline(time.Now().Add(2 * time.Second))
				n, werr := pkt.WriteTo(payload, sinkAddr)
				if werr != nil {
					return
				}
				perBytes[i].Add(int64(n))
			}
		}()
	}
	close(start)
	wg.Wait()
	elapsed := time.Since(t0).Seconds()
	if elapsed < 0.1 {
		elapsed = 0.1
	}

	var total int64
	perStreamMbps = make([]float64, streams)
	for i := 0; i < streams; i++ {
		b := perBytes[i].Load()
		total += b
		perStreamMbps[i] = (float64(b) * 8) / (elapsed * 1e6)
	}
	aggMbps = (float64(total) * 8) / (elapsed * 1e6)
	symmetry = streamThroughputSymmetry(perStreamMbps)
	return aggMbps, perStreamMbps, symmetry
}

func formatStreamMbps(mbps []float64, dur time.Duration) string {
	_ = dur
	parts := make([]string, len(mbps))
	for i, m := range mbps {
		parts[i] = fmt.Sprintf("%.0f", m)
	}
	return strings.Join(parts, " ")
}

// streamThroughputSymmetry returns min/max per-stream Mbps ratio (1.0 = perfectly fair).
func streamThroughputSymmetry(mbps []float64) float64 {
	if len(mbps) == 0 {
		return 1
	}
	minV, maxV := math.MaxFloat64, 0.0
	for _, m := range mbps {
		if m < minV {
			minV = m
		}
		if m > maxV {
			maxV = m
		}
	}
	if maxV <= 0 {
		return 1
	}
	return minV / maxV
}
