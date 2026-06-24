package masque

// Prod-stack CONNECT-UDP H2 burst localize: LaunchMasqueStack + masque.Endpoint (CM.Runtime) + SOCKS5 ASSOCIATE.
// Parity with docker connect-udp-h2 (sing-box client/server); synth-first gate before docker KPI.

import (
	"crypto/tls"
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"testing"
	"time"

	"github.com/quic-go/quic-go/http3"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/masque/server"
	"github.com/sagernet/sing-box/route"
	"github.com/sagernet/sing-box/transport/masque/connectudp"
	cudpframe "github.com/sagernet/sing-box/transport/masque/connectudp/frame"
	cudprelay "github.com/sagernet/sing-box/transport/masque/connectudp/relay"
	TM "github.com/sagernet/sing-box/transport/masque"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/protocol/socks"
	"github.com/yosida95/uritemplate/v3"

	_ "github.com/sagernet/sing-box/internal/http2xconnect"
)

const (
	endpointConnectUDPBurstDuration   = 2 * time.Second
	endpointConnectUDPBurstMinMbps    = 490.0 // prod LaunchMasqueStack variance band (target 500)
	endpointConnectUDPBurstWriteStall = 500 * time.Millisecond
)

func startEndpointH2ConnectUDPProdLaunchStack(t *testing.T) int {
	t.Helper()
	var udpTemplate *uritemplate.Template
	var udpProxy cudprelay.Proxy
	t.Cleanup(func() { _ = udpProxy.Close() })

	mux := http.NewServeMux()
	mux.HandleFunc("/masque/udp/{target_host}/{target_port}", func(w http.ResponseWriter, r *http.Request) {
		if udpTemplate == nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		req, err := cudpframe.ParseRequest(r, udpTemplate)
		if err != nil {
			var perr *cudpframe.RequestParseError
			if errors.As(err, &perr) {
				w.WriteHeader(perr.HTTPStatus)
				return
			}
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		server.HandleConnectUDP(w, r, req, &udpProxy, server.ConnectUDPTargetPolicy{AllowPrivateTargets: true})
	})

	h3TLS := TM.InProcessH3TestTLS(t)
	h3TLS = h3TLS.Clone()
	h3TLS.NextProtos = []string{http3.NextProtoH3}
	collateralTLS := TM.InProcessH3TestTLS(t)
	collateralTLS = collateralTLS.Clone()
	collateralTLS.NextProtos = []string{"h2", "http/1.1"}

	stack, err := server.LaunchMasqueStack(server.LaunchMasqueStackConfig{
		Handler:       mux,
		ListenHost:    "127.0.0.1",
		ListenPort:    0,
		HTTP3TLS:      h3TLS,
		CollateralTLS: collateralTLS,
		ValidateUDP:   func(net.PacketConn) error { return nil },
	})
	if err != nil {
		t.Fatalf("LaunchMasqueStack: %v", err)
	}
	if stack == nil || stack.TCPTLSListener == nil {
		t.Fatal("expected TCP/TLS collateral listener")
	}
	t.Cleanup(func() {
		if shutErr := server.ShutdownMasqueEndpoint(server.ShutdownMasqueEndpointConfig{Stack: stack}); shutErr != nil {
			t.Errorf("shutdown LaunchMasqueStack: %v", shutErr)
		}
	})

	tcpAddr, ok := stack.TCPTLSListener.Addr().(*net.TCPAddr)
	if !ok || tcpAddr == nil {
		t.Fatalf("unexpected listener addr: %T", stack.TCPTLSListener.Addr())
	}
	port := tcpAddr.Port
	rawTpl := fmt.Sprintf("https://127.0.0.1:%d/masque/udp/{target_host}/{target_port}", port)
	udpTemplate, err = uritemplate.New(rawTpl)
	if err != nil {
		t.Fatalf("udp template: %v", err)
	}
	time.Sleep(30 * time.Millisecond)
	return port
}

func endpointRunUDPSequencedSink(t *testing.T, runID uint32) (*net.UDPAddr, *connectudp.SequencedSink) {
	t.Helper()
	c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("listen sequenced sink: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	const buf = 4 << 20
	_ = c.SetReadBuffer(buf)
	_ = c.SetWriteBuffer(buf)
	sink := connectudp.NewSequencedSink(runID)
	go func() {
		pkt := make([]byte, 2048)
		for {
			n, _, rerr := c.ReadFrom(pkt)
			if rerr != nil {
				return
			}
			if n > 0 {
				sink.Record(pkt[:n])
			}
		}
	}()
	return c.LocalAddr().(*net.UDPAddr), sink
}

func endpointBurstWriteTo(pkt net.PacketConn, payload []byte, dest *net.UDPAddr) error {
	deadline := time.Now().Add(endpointConnectUDPBurstWriteStall)
	for {
		_ = pkt.SetWriteDeadline(deadline)
		_, err := pkt.WriteTo(payload, dest)
		if err == nil {
			return nil
		}
		if time.Now().After(deadline) {
			return err
		}
	}
}

func endpointBurstSearch(
	t *testing.T,
	pkt net.PacketConn,
	sinkAddr *net.UDPAddr,
	seqSink *connectudp.SequencedSink,
	label string,
) float64 {
	t.Helper()
	const baseRunID = uint32(0xE0C10000)
	payloadLen := connectudp.DefaultBenchUDPPayloadLen
	probe := func(targetMbit float64, probeN uint32) connectudp.SequencedStats {
		runID := baseRunID | probeN
		seqSink.Reset(runID)
		deadline := time.Now().Add(endpointConnectUDPBurstDuration)
		var seq uint64
		var sent int
		var paceSlot time.Time
		for time.Now().Before(deadline) {
			p := connectudp.BuildProbePayload(seq, runID, payloadLen)
			if err := endpointBurstWriteTo(pkt, p, sinkAddr); err != nil {
				t.Fatalf("%s burst %.1f Mbps stalled seq=%d sent=%d: %v", label, targetMbit, seq, sent, err)
			}
			sent++
			seq++
			if targetMbit > 0 {
				connectudp.PaceSleepUntil(&paceSlot, payloadLen, targetMbit)
			}
		}
		connectudp.FlushPacketConnWrites(pkt)
		time.Sleep(500 * time.Millisecond)
		if err := connectudp.DrainPacketConnUpload(pkt, connectudp.DefaultUploadDrainTimeout); err != nil {
			t.Fatalf("%s burst %.1f Mbps upload drain: %v", label, targetMbit, err)
		}
		time.Sleep(200 * time.Millisecond)
		return seqSink.Analyze(sent, payloadLen)
	}
	pass := func(st connectudp.SequencedStats) bool {
		return st.BurstZeroLossOK(payloadLen, connectudp.DefaultBurstMinRxRatio)
	}
	var probeN uint32
	lo, hi := 8.0, 500.0
	var bestMbps float64
	var best connectudp.SequencedStats
	for step := 0; step < 10; step++ {
		probeN++
		mid := (lo + hi) / 2
		st := probe(mid, probeN)
		t.Logf("%s burst search %d: target=%.1f Mbps loss=%.2f%% rx=%d/%d",
			label, step+1, mid, st.LossPct, st.RxPkts, st.SentPkts)
		if pass(st) {
			lo = mid
			best = st
			bestMbps = mid
		} else {
			hi = mid
		}
		if hi-lo < 4 {
			break
		}
	}
	for step := bestMbps + 4; step <= hi+4; step += 4 {
		probeN++
		st := probe(step, probeN)
		t.Logf("%s burst refine: target=%.1f Mbps loss=%.2f%% rx=%d/%d",
			label, step, st.LossPct, st.RxPkts, st.SentPkts)
		if pass(st) {
			best = st
			bestMbps = step
		} else {
			break
		}
	}
	if !best.BurstZeroLossOK(payloadLen, connectudp.DefaultBurstMinRxRatio) {
		t.Fatalf("%s burst failed zero-loss gate: %+v", label, best)
	}
	return bestMbps
}

func endpointBenchConnectUDPH2CoreClientBurst(t *testing.T, proxyPort int) float64 {
	t.Helper()
	sinkAddr, seqSink := endpointRunUDPSequencedSink(t, 0xE0C20000|1)
	waitCtx, cancel := context.WithTimeout(context.Background(), 10*endpointConnectUDPBurstDuration+30*time.Second)
	t.Cleanup(cancel)
	baseDial := func(ctx context.Context, network, addr string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, network, addr)
	}
	session, err := TM.CoreClientFactory{}.NewSession(waitCtx, TM.ClientOptions{
		Server:                   "127.0.0.1",
		ServerPort:               uint16(proxyPort),
		TransportMode:            option.MasqueTransportModeConnectUDP,
		MasqueEffectiveHTTPLayer: option.MasqueHTTPLayerH2,
		MasqueQUICCryptoTLS:      &tls.Config{InsecureSkipVerify: true},
		TCPDial:                  baseDial,
	})
	if err != nil {
		t.Fatalf("CoreClientFactory session: %v", err)
	}
	t.Cleanup(func() { _ = session.Close() })
	pkt, err := session.ListenPacket(waitCtx, M.Socksaddr{
		Addr: netip.MustParseAddr(sinkAddr.IP.String()),
		Port: uint16(sinkAddr.Port),
	})
	if err != nil {
		t.Fatalf("ListenPacket: %v", err)
	}
	t.Cleanup(func() { _ = pkt.Close() })
	route.TuneUDPPacketConn(pkt)
	return endpointBurstSearch(t, pkt, sinkAddr, seqSink, "core-direct")
}

func endpointBenchConnectUDPH2SocksBurst(t *testing.T, proxyPort int) float64 {
	t.Helper()
	sinkAddr, seqSink := endpointRunUDPSequencedSink(t, 0xE0C00000|1)

	epRaw, err := NewEndpoint(context.Background(), nil, log.StdLogger(), "masque-udp-h2", option.MasqueEndpointOptions{
		ServerOptions: option.ServerOptions{Server: "127.0.0.1", ServerPort: uint16(proxyPort)},
		HopPolicy:     option.MasqueHopPolicySingle,
		TransportMode: option.MasqueTransportModeConnectUDP,
		TCPTransport:  option.MasqueTCPTransportConnectStream,
		HTTPLayer:     option.MasqueHTTPLayerH2,
		TemplateUDP:   fmt.Sprintf("https://127.0.0.1:%d/masque/udp/{target_host}/{target_port}", proxyPort),
		OutboundTLS: &option.OutboundTLSOptions{
			Enabled:    true,
			Insecure:   true,
			ServerName: "127.0.0.1",
		},
	})
	if err != nil {
		t.Fatalf("NewEndpoint: %v", err)
	}
	ep := epRaw.(*Endpoint)
	t.Cleanup(func() { _ = ep.Close() })
	if err := ep.Start(adapter.StartStatePostStart); err != nil {
		t.Fatalf("endpoint Start: %v", err)
	}
	waitEndpointReady(t, ep)
	socksPort := startEndpointH2ConnectStreamSocksRouter(t, ep)

	dialer := socks.NewClient(N.SystemDialer, M.ParseSocksaddrHostPort("127.0.0.1", socksPort), socks.Version5, "", "")
	ctx, cancel := context.WithTimeout(context.Background(), 10*endpointConnectUDPBurstDuration+30*time.Second)
	t.Cleanup(cancel)
	pkt, err := dialer.ListenPacket(ctx, M.ParseSocksaddrHostPort(sinkAddr.IP.String(), uint16(sinkAddr.Port)))
	if err != nil {
		t.Fatalf("socks udp associate: %v", err)
	}
	t.Cleanup(func() { _ = pkt.Close() })
	route.TuneUDPPacketConn(pkt)
	return endpointBurstSearch(t, pkt, sinkAddr, seqSink, "endpoint-socks")
}

// TestLocalizeConnectUDPBurstProdLaunchStackVsCoreClient bisects docker gap: same LaunchMasqueStack server.
func TestLocalizeConnectUDPBurstProdLaunchStackVsCoreClient(t *testing.T) {
	proxyPort := startEndpointH2ConnectUDPProdLaunchStack(t)
	coreMbps := endpointBenchConnectUDPH2CoreClientBurst(t, proxyPort)
	epMbps := endpointBenchConnectUDPH2SocksBurst(t, proxyPort)
	t.Logf("LaunchMasqueStack burst: CoreClientFactory=%.1f Endpoint=%.1f Mbit/s", coreMbps, epMbps)
	if coreMbps >= 450 && epMbps < 300 {
		t.Fatalf("server OK (%.1f) but Endpoint path %.1f — CM.Runtime/client TLS gap", coreMbps, epMbps)
	}
	if coreMbps < 300 && epMbps < 300 {
		t.Fatalf("both paths slow (core=%.1f ep=%.1f) — LaunchMasqueStack/prod server gap vs lightweight proxy", coreMbps, epMbps)
	}
}

// TestEndpointConnectUDPH2SocksBurstProdLaunchStack localizes docker connect-udp-h2 burst KPI in-proc
// (LaunchMasqueStack server + masque.Endpoint + SOCKS5 ASSOCIATE).
func TestEndpointConnectUDPH2SocksBurstProdLaunchStack(t *testing.T) {
	proxyPort := startEndpointH2ConnectUDPProdLaunchStack(t)
	mbps := endpointBenchConnectUDPH2SocksBurst(t, proxyPort)
	if mbps < 400 {
		t.Logf("prod stack burst retry after %.1f Mbit/s (first probe variance)", mbps)
		mbps = endpointBenchConnectUDPH2SocksBurst(t, proxyPort)
	}
	t.Logf("prod launch stack h2 socks burst max zero-loss: %.1f Mbit/s (want >= %.0f)", mbps, endpointConnectUDPBurstMinMbps)
	if mbps < endpointConnectUDPBurstMinMbps {
		t.Fatalf("prod stack burst %.1f < %.0f Mbit/s — fix prod LaunchMasqueStack path before docker verify",
			mbps, endpointConnectUDPBurstMinMbps)
	}
}
