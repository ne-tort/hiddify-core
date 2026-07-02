package masque

// Parallel/scaling bench helpers (probe + GATE parallel scaling).

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

	"github.com/sagernet/sing-box/transport/masque/connectudp"
	M "github.com/sagernet/sing/common/metadata"
)

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
				if err := writeToWithStallGuard(t, pkt, payload, sinkAddr, 2*time.Second); err != nil {
					return
				}
				perBytes[i].Add(int64(len(payload)))
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

// benchParallelConnectUDPMultiSession runs N independent CoreSessions with one upload stream each.
// Contrasts with benchParallelConnectUDPStreams (one session, N streams) for QUIC mux attribution.
func benchParallelConnectUDPMultiSession(
	t *testing.T,
	layer string,
	proxyPort int,
	sinkAddr *net.UDPAddr,
	sessions int,
	dur time.Duration,
	payloadLen int,
) (aggMbps float64, perSessionMbps []float64, symmetry float64) {
	t.Helper()
	if sessions < 1 {
		sessions = 1
	}

	openSession := func() (ClientSession, context.Context, func()) {
		t.Helper()
		waitCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		var session ClientSession
		var err error
		switch layer {
		case "h2":
			session, waitCtx = newConnectUDPProdProfileH2SessionWithLink(t, proxyPort, instantH2Link{})
			return session, waitCtx, func() { cancel(); _ = session.Close() }
		case "h3":
			session, err = (CoreClientFactory{}).NewSession(waitCtx, ClientOptions{
				Server:              "127.0.0.1",
				ServerPort:          uint16(proxyPort),
				MasqueQUICCryptoTLS: &tls.Config{InsecureSkipVerify: true},
			})
			if err != nil {
				cancel()
				t.Fatalf("session: %v", err)
			}
			return session, waitCtx, func() { cancel(); _ = session.Close() }
		default:
			cancel()
			t.Fatalf("unknown layer %q", layer)
			return nil, nil, nil
		}
	}

	pkts := make([]net.PacketConn, sessions)
	cleanups := make([]func(), sessions)
	for i := 0; i < sessions; i++ {
		session, waitCtx, cleanup := openSession()
		pkt, err := session.ListenPacket(waitCtx, M.Socksaddr{
			Addr: netip.MustParseAddr(sinkAddr.IP.String()),
			Port: uint16(sinkAddr.Port),
		})
		if err != nil {
			cleanup()
			for j := 0; j < i; j++ {
				if pkts[j] != nil {
					_ = pkts[j].Close()
				}
				cleanups[j]()
			}
			t.Fatalf("ListenPacket session %d: %v", i, err)
		}
		pkts[i] = pkt
		cleanups[i] = func() {
			_ = pkt.Close()
			cleanup()
		}
	}
	defer func() {
		for _, c := range cleanups {
			c()
		}
	}()

	payload := make([]byte, payloadLen)
	perBytes := make([]atomic.Int64, sessions)
	var wg sync.WaitGroup
	start := make(chan struct{})
	t0 := time.Now()
	deadline := t0.Add(dur)
	wg.Add(sessions)
	for i := 0; i < sessions; i++ {
		i := i
		pkt := pkts[i]
		go func() {
			defer wg.Done()
			<-start
			for time.Now().Before(deadline) {
				if err := writeToWithStallGuard(t, pkt, payload, sinkAddr, 2*time.Second); err != nil {
					return
				}
				perBytes[i].Add(int64(len(payload)))
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
	perSessionMbps = make([]float64, sessions)
	for i := 0; i < sessions; i++ {
		b := perBytes[i].Load()
		total += b
		perSessionMbps[i] = (float64(b) * 8) / (elapsed * 1e6)
	}
	aggMbps = (float64(total) * 8) / (elapsed * 1e6)
	symmetry = streamThroughputSymmetry(perSessionMbps)
	return aggMbps, perSessionMbps, symmetry
}

func formatStreamMbps(mbps []float64, dur time.Duration) string {
	_ = dur
	parts := make([]string, len(mbps))
	for i, m := range mbps {
		parts[i] = fmt.Sprintf("%.0f", m)
	}
	return strings.Join(parts, " ")
}

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

func gateConnectUDPParallelScaling(t *testing.T, layer string, streams int) {
	t.Helper()
	if streams < 2 {
		streams = 2
	}
	dur := connectUDPSynthProdBenchDuration
	payloadLen := connectudp.DefaultBenchUDPPayloadLen

	sink, _ := runUDPSink(t, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	sinkAddr := sink.LocalAddr().(*net.UDPAddr)

	var proxyPort int
	switch layer {
	case "h2":
		proxyPort = startInProcessH2UDPConnectProxy(t)
	case "h3":
		proxyPort = startInProcessMasqueUDPProxy(t, func(mux *http.ServeMux, p int) {
			registerMasqueUDPProxyHandler(t, mux, p)
		})
	default:
		t.Fatalf("unknown layer %q", layer)
	}

	_, singlePerStream, _ := benchParallelConnectUDPStreams(t, layer, proxyPort, sinkAddr, 1, dur, payloadLen)
	singleMbps := 0.0
	if len(singlePerStream) > 0 {
		singleMbps = singlePerStream[0]
	}

	aggMbps, perStreamMbps, symmetry := benchParallelConnectUDPStreams(t, layer, proxyPort, sinkAddr, streams, dur, payloadLen)
	scaleEff := 0.0
	if singleMbps > 0 && streams > 0 {
		scaleEff = aggMbps / (singleMbps * float64(streams))
	}
	minAgg := connectUDPParallelScalingMinAggMbps(layer, streams, singleMbps)
	t.Logf("GATE parallel %s x%d: single=%.1f agg=%.1f eff=%.2f sym=%.2f per=[%s] (min %.1f)",
		layer, streams, singleMbps, aggMbps, scaleEff, symmetry, formatStreamMbps(perStreamMbps, dur), minAgg)
	if symmetry < 0.55 {
		t.Fatalf("%s parallel x%d stream symmetry %.2f < 0.55 (uneven fan-out)", layer, streams, symmetry)
	}
	if aggMbps < minAgg*(1-connectUDPSynthInstantGateSlackPct) {
		t.Fatalf("%s parallel x%d aggregate %.1f Mbit/s < min %.1f (single %.1f)", layer, streams, aggMbps, minAgg, singleMbps)
	}
	if scaleEff < 0.35 && streams >= 4 {
		t.Logf("OPEN: %s parallel x%d scale efficiency %.2f — multi-flow throughput ceiling (Linux Docker reference)", layer, streams, scaleEff)
	}
}
