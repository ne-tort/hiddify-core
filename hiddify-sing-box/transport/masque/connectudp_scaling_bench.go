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

	"github.com/sagernet/sing-box/option"
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

	var singleMbps float64
	switch layer {
	case "h2":
		_, singleMbps, _ = benchConnectUDPProdProfileH2Upload(t, instantH2Link{}, dur, 0, payloadLen)
	case "h3":
		_, singleMbps, _ = benchConnectUDPProdProfileH3Upload(t, instantDatagramLink{}, dur, 0, payloadLen)
	default:
		t.Fatalf("unknown layer %q", layer)
	}

	var proxyPort int
	switch layer {
	case "h2":
		proxyPort = startInProcessH2UDPConnectProxy(t)
	case "h3":
		proxyPort = startInProcessMasqueUDPProxy(t, func(mux *http.ServeMux, p int) {
			registerMasqueUDPProxyHandler(t, mux, p)
		})
	}

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
	var totalBytes int64
	perStreamMbps := make([]float64, streams)
	for i := 0; i < streams; i++ {
		b := perBytes[i].Load()
		totalBytes += b
		perStreamMbps[i] = (float64(b) * 8) / (elapsed * 1e6)
	}
	aggMbps := (float64(totalBytes) * 8) / (elapsed * 1e6)
	symmetry := streamThroughputSymmetry(perStreamMbps)
	scaleEff := 0.0
	if singleMbps > 0 && streams > 0 {
		scaleEff = aggMbps / (singleMbps * float64(streams))
	}
	minAgg := singleMbps * float64(streams) * 0.7
	if singleMbps >= connectUDPSynthProdMinMbps*(1-connectUDPSynthInstantGateSlackPct) {
		minAgg = connectUDPSynthProdMinMbps * float64(streams) * 0.7
		if minAgg > connectUDPSynthProdMinMbps {
			minAgg = connectUDPSynthProdMinMbps
		}
	} else if minAgg > 500 {
		minAgg = 500
	}
	if minAgg > singleMbps*0.55 {
		minAgg = singleMbps * 0.55
		if minAgg < 250 {
			minAgg = 250
		}
	}
	if minAgg > 500 {
		minAgg = 500
	}
	t.Logf("GATE parallel %s x%d: single=%.1f agg=%.1f eff=%.2f sym=%.2f per=[%s] (min %.1f)",
		layer, streams, singleMbps, aggMbps, scaleEff, symmetry, formatStreamMbps(perStreamMbps, dur), minAgg)
	if symmetry < 0.55 {
		t.Fatalf("%s parallel x%d stream symmetry %.2f < 0.55 (uneven fan-out)", layer, streams, symmetry)
	}
	if aggMbps < minAgg*(1-connectUDPSynthInstantGateSlackPct) {
		t.Fatalf("%s parallel x%d aggregate %.1f Mbit/s < min %.1f (single %.1f)", layer, streams, aggMbps, minAgg, singleMbps)
	}
}
