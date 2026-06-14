package masque

// GATE-CONNECT-UDP-SYNTH: prod profile (transport_mode=connect_udp) burst/paced upload gates with diagnostics.

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"testing"
	"time"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/transport/masque/connectudp"
	M "github.com/sagernet/sing/common/metadata"
)

func benchConnectUDPProdProfileH3Upload(
	t *testing.T,
	link datagramTransportLink,
	duration time.Duration,
	targetMbit float64,
	payloadLen int,
) (int64, float64, error) {
	t.Helper()
	if payloadLen <= 0 {
		payloadLen = connectudp.DefaultBenchUDPPayloadLen
	}
	sink, _ := runUDPSink(t, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	sinkAddr := sink.LocalAddr().(*net.UDPAddr)

	proxyPort := startInProcessMasqueUDPProxy(t, func(mux *http.ServeMux, proxyPort int) {
		registerMasqueUDPProxyHandler(t, mux, proxyPort)
	})

	waitCtx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()

	opts := ClientOptions{
		Server:              "127.0.0.1",
		ServerPort:          uint16(proxyPort),
		TransportMode:       option.MasqueTransportModeConnectUDP,
		MasqueQUICCryptoTLS: &tls.Config{InsecureSkipVerify: true},
	}
	if dial := link.quicDialOverride(); dial != nil {
		opts.QUICDial = dial
	}

	session, err := (CoreClientFactory{}).NewSession(waitCtx, opts)
	if err != nil {
		return 0, 0, err
	}
	defer func() { _ = session.Close() }()
	if !session.Capabilities().ConnectUDP {
		return 0, 0, errors.New("connect-udp prod: ConnectUDP capability missing")
	}

	pkt, err := session.ListenPacket(waitCtx, M.Socksaddr{
		Addr: netip.MustParseAddr(sinkAddr.IP.String()),
		Port: uint16(sinkAddr.Port),
	})
	if err != nil {
		return 0, 0, err
	}
	defer func() { _ = pkt.Close() }()

	return benchConnectUDPPacketUpload(pkt, sinkAddr, duration, targetMbit, payloadLen)
}

func benchConnectUDPProdProfileH2Upload(
	t *testing.T,
	link h2TransportLink,
	duration time.Duration,
	targetMbit float64,
	payloadLen int,
) (int64, float64, error) {
	t.Helper()
	if payloadLen <= 0 {
		payloadLen = connectudp.DefaultBenchUDPPayloadLen
	}
	sink, _ := runUDPSink(t, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	sinkAddr := sink.LocalAddr().(*net.UDPAddr)

	proxyPort := startInProcessH2UDPConnectProxy(t)
	session, waitCtx := newConnectUDPProdProfileH2SessionWithLink(t, proxyPort, link)

	pkt, err := session.ListenPacket(waitCtx, M.Socksaddr{
		Addr: netip.MustParseAddr(sinkAddr.IP.String()),
		Port: uint16(sinkAddr.Port),
	})
	if err != nil {
		return 0, 0, err
	}
	defer func() { _ = pkt.Close() }()

	return benchConnectUDPPacketUpload(pkt, sinkAddr, duration, targetMbit, payloadLen)
}

func newConnectUDPProdProfileH2SessionWithLink(t *testing.T, proxyPort int, link h2TransportLink) (ClientSession, context.Context) {
	return newConnectUDPProdProfileH2SessionWithLinkTB(t, proxyPort, link)
}

func newConnectUDPProdProfileH2SessionWithLinkTB(tb testing.TB, proxyPort int, link h2TransportLink) (ClientSession, context.Context) {
	tb.Helper()
	if link == nil {
		link = instantH2Link{}
	}
	waitCtx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	tb.Cleanup(cancel)
	baseDial := func(ctx context.Context, network, addr string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, network, addr)
	}
	session, err := (CoreClientFactory{}).NewSession(waitCtx, ClientOptions{
		Server:                   "127.0.0.1",
		ServerPort:               uint16(proxyPort),
		TransportMode:            option.MasqueTransportModeConnectUDP,
		MasqueEffectiveHTTPLayer: option.MasqueHTTPLayerH2,
		MasqueQUICCryptoTLS:      &tls.Config{InsecureSkipVerify: true},
		TCPDial: func(ctx context.Context, network, addr string) (net.Conn, error) {
			conn, err := baseDial(ctx, network, addr)
			if err != nil {
				return nil, err
			}
			return link.wrapTCP(conn), nil
		},
	})
	if err != nil {
		tb.Fatalf("new connect-udp-h2 prod session: %v", err)
	}
	tb.Cleanup(func() { _ = session.Close() })
	return session, waitCtx
}

func benchConnectUDPPacketUpload(
	pkt net.PacketConn,
	sinkAddr *net.UDPAddr,
	duration time.Duration,
	targetMbit float64,
	payloadLen int,
) (int64, float64, error) {
	payload := make([]byte, payloadLen)
	for i := range payload {
		payload[i] = byte(i % 251)
	}
	pace := connectudp.PaceInterval(payloadLen, targetMbit)
	deadline := time.Now().Add(duration)
	var sent int64
	for time.Now().Before(deadline) {
		_ = pkt.SetWriteDeadline(time.Now().Add(2 * time.Second))
		n, err := pkt.WriteTo(payload, sinkAddr)
		if err != nil {
			if sent > 0 {
				break
			}
			return 0, 0, err
		}
		sent += int64(n)
		if pace > 0 {
			time.Sleep(pace)
		}
	}
	secs := duration.Seconds()
	if secs <= 0 {
		secs = 1
	}
	return sent, float64(sent*8) / secs / 1e6, nil
}

type connectUDPProdUploadHandle struct {
	pkt      net.PacketConn
	sinkAddr *net.UDPAddr
	cleanup  func()
}

func startConnectUDPProdH3UploadHandle(tb testing.TB) *connectUDPProdUploadHandle {
	tb.Helper()
	sink, _ := runUDPSink(tb, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	sinkAddr := sink.LocalAddr().(*net.UDPAddr)

	proxyPort := startInProcessMasqueUDPProxy(tb, func(mux *http.ServeMux, proxyPort int) {
		registerMasqueUDPProxyHandler(tb, mux, proxyPort)
	})

	waitCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	session, err := (CoreClientFactory{}).NewSession(waitCtx, ClientOptions{
		Server:              "127.0.0.1",
		ServerPort:          uint16(proxyPort),
		TransportMode:       option.MasqueTransportModeConnectUDP,
		MasqueQUICCryptoTLS: &tls.Config{InsecureSkipVerify: true},
	})
	if err != nil {
		tb.Fatalf("connect-udp-h3 upload handle: %v", err)
	}
	pkt, err := session.ListenPacket(waitCtx, M.Socksaddr{
		Addr: netip.MustParseAddr(sinkAddr.IP.String()),
		Port: uint16(sinkAddr.Port),
	})
	if err != nil {
		_ = session.Close()
		cancel()
		tb.Fatalf("ListenPacket connect-udp-h3: %v", err)
	}
	return &connectUDPProdUploadHandle{
		pkt:      pkt,
		sinkAddr: sinkAddr,
		cleanup: func() {
			_ = pkt.Close()
			_ = session.Close()
			cancel()
		},
	}
}

func startConnectUDPProdH2UploadHandle(tb testing.TB) *connectUDPProdUploadHandle {
	tb.Helper()
	sink, _ := runUDPSink(tb, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	sinkAddr := sink.LocalAddr().(*net.UDPAddr)

	proxyPort := startInProcessH2UDPConnectProxy(tb)
	session, waitCtx := newConnectUDPProdProfileH2SessionWithLinkTB(tb, proxyPort, instantH2Link{})
	pkt, err := session.ListenPacket(waitCtx, M.Socksaddr{
		Addr: netip.MustParseAddr(sinkAddr.IP.String()),
		Port: uint16(sinkAddr.Port),
	})
	if err != nil {
		tb.Fatalf("ListenPacket connect-udp-h2: %v", err)
	}
	return &connectUDPProdUploadHandle{
		pkt:      pkt,
		sinkAddr: sinkAddr,
		cleanup: func() {
			_ = pkt.Close()
			_ = session.Close()
		},
	}
}

func (h *connectUDPProdUploadHandle) close() {
	if h != nil && h.cleanup != nil {
		h.cleanup()
	}
}

func (h *connectUDPProdUploadHandle) uploadOnce(nbytes int64) (int64, error) {
	payload := make([]byte, connectudp.DefaultBenchUDPPayloadLen)
	var sent int64
	for sent < nbytes {
		_ = h.pkt.SetWriteDeadline(time.Now().Add(5 * time.Second))
		n, err := h.pkt.WriteTo(payload, h.sinkAddr)
		if err != nil {
			return sent, err
		}
		sent += int64(n)
	}
	return sent, nil
}

// TestGATEConnectUDPH3SynthProdBurstUpload locks connect-udp-h3 prod burst upload on instant link.
func TestGATEConnectUDPH3SynthProdBurstUpload(t *testing.T) {
	dur := connectUDPSynthProdBenchDuration
	bytes, mbps, err := benchConnectUDPProdProfileH3Upload(t, instantDatagramLink{}, dur, 0, connectudp.DefaultBenchUDPPayloadLen)
	if err != nil {
		t.Fatalf("connect-udp-h3 prod burst: %v", err)
	}
	t.Logf("GATE-CONNECT-UDP-SYNTH h3 burst: %.1f Mbit/s (%d bytes)", mbps, bytes)
	if mbps < connectUDPSynthProdBurstMinMbps {
		t.Fatal(synthKPIDiagnostic("L4 connect-udp-h3 prod", "udp_up burst", mbps, connectUDPSynthProdBurstMinMbps,
			"instant QUIC datagram path — check split/window/scheduler"))
	}
}

// TestGATEConnectUDPH2SynthProdBurstUpload locks connect-udp-h2 prod burst upload on instant link.
func TestGATEConnectUDPH2SynthProdBurstUpload(t *testing.T) {
	dur := connectUDPSynthProdBenchDuration
	bytes, mbps, err := benchConnectUDPProdProfileH2Upload(t, instantH2Link{}, dur, 0, connectudp.DefaultBenchUDPPayloadLen)
	if err != nil {
		t.Fatalf("connect-udp-h2 prod burst: %v", err)
	}
	t.Logf("GATE-CONNECT-UDP-SYNTH h2 burst: %.1f Mbit/s (%d bytes)", mbps, bytes)
	if mbps < connectUDPSynthProdBurstMinMbps {
		t.Fatal(synthKPIDiagnostic("L4 connect-udp-h2 prod", "udp_up burst", mbps, connectUDPSynthProdBurstMinMbps,
			"H2 capsule path — check DatagramSplitConn / flush / relay"))
	}
}

// TestGATEConnectUDPPairedSynthBurstUpload ensures H3 burst is not materially behind H2 on prod profile.
func TestGATEConnectUDPPairedSynthBurstUpload(t *testing.T) {
	dur := connectUDPSynthProdBenchDuration
	_, h2Mbps, err := benchConnectUDPProdProfileH2Upload(t, instantH2Link{}, dur, 0, connectudp.DefaultBenchUDPPayloadLen)
	if err != nil {
		t.Fatalf("connect-udp-h2 prod burst (paired): %v", err)
	}
	_, h3Mbps, err := benchConnectUDPProdProfileH3Upload(t, instantDatagramLink{}, dur, 0, connectudp.DefaultBenchUDPPayloadLen)
	if err != nil {
		t.Fatalf("connect-udp-h3 prod burst (paired): %v", err)
	}
	ratio := h3Mbps / h2Mbps
	t.Logf("GATE-CONNECT-UDP-SYNTH paired burst: H2=%.1f H3=%.1f ratio=%.2f", h2Mbps, h3Mbps, ratio)
	if h3Mbps < connectUDPSynthProdBurstMinMbps {
		t.Fatal(synthKPIDiagnostic("L4 connect-udp-h3 prod", "udp_up burst", h3Mbps, connectUDPSynthProdBurstMinMbps,
			"paired with H2 on burst upload"))
	}
	if ratio < connectUDPSynthParityMinRatio {
		t.Fatal(synthKPIDiagnostic("L4 connect-udp paired", "H3/H2 burst ratio", ratio, connectUDPSynthParityMinRatio,
			"H3 must stay within 15% of H2 burst on prod profile"))
	}
}

// TestGATEConnectUDPH3SynthProdPacedUpload locks in-proc paced band @ docker target 8 Mbit/s (not WAN KPI).
func TestGATEConnectUDPH3SynthProdPacedUpload(t *testing.T) {
	dur := connectUDPSynthProdBenchDuration
	bytes, mbps, err := benchConnectUDPProdProfileH3Upload(
		t, instantDatagramLink{}, dur, dockerBenchUDPTargetMbit, connectudp.DefaultBenchUDPPayloadLen,
	)
	if err != nil {
		t.Fatalf("connect-udp-h3 prod paced: %v", err)
	}
	t.Logf("GATE-CONNECT-UDP-SYNTH h3 paced: %.1f Mbit/s (%d bytes)", mbps, bytes)
	if bytes < localizeBenchMinBytes/4 {
		t.Fatalf("paced upload=%d bytes too small for profiling", bytes)
	}
	if mbps < connectUDPSynthInProcPacedMinMbps || mbps > connectUDPSynthInProcPacedMaxMbps {
		t.Fatalf("%s; docker calibrated ~%.2f Mbit/s @ netem %d ms",
			synthKPIDiagnostic("L4 connect-udp-h3 prod", "udp_up paced", mbps, connectUDPSynthInProcPacedMinMbps,
				"in-proc band "+formatSynthMbps(connectUDPSynthInProcPacedMinMbps)+
					"–"+formatSynthMbps(connectUDPSynthInProcPacedMaxMbps)),
			connectudp.ExpectedPacedGoodputMbit(dockerBenchUDPTargetMbit),
			connectudp.DefaultBenchNetemDelayMS,
		)
	}
}

// TestGATEConnectUDPH2SynthProdPacedUpload locks in-proc paced band for connect-udp-h2 prod profile.
func TestGATEConnectUDPH2SynthProdPacedUpload(t *testing.T) {
	dur := connectUDPSynthProdBenchDuration
	bytes, mbps, err := benchConnectUDPProdProfileH2Upload(
		t, instantH2Link{}, dur, dockerBenchUDPTargetMbit, connectudp.DefaultBenchUDPPayloadLen,
	)
	if err != nil {
		t.Fatalf("connect-udp-h2 prod paced: %v", err)
	}
	t.Logf("GATE-CONNECT-UDP-SYNTH h2 paced: %.1f Mbit/s (%d bytes)", mbps, bytes)
	if bytes < localizeBenchMinBytes/4 {
		t.Fatalf("paced upload=%d bytes too small for profiling", bytes)
	}
	if mbps < connectUDPSynthInProcPacedMinMbps || mbps > connectUDPSynthInProcPacedMaxMbps {
		t.Fatalf("%s; docker calibrated ~%.2f Mbit/s @ netem %d ms",
			synthKPIDiagnostic("L4 connect-udp-h2 prod", "udp_up paced", mbps, connectUDPSynthInProcPacedMinMbps,
				"in-proc band "+formatSynthMbps(connectUDPSynthInProcPacedMinMbps)+
					"–"+formatSynthMbps(connectUDPSynthInProcPacedMaxMbps)),
			connectudp.ExpectedPacedGoodputMbit(dockerBenchUDPTargetMbit),
			connectudp.DefaultBenchNetemDelayMS,
		)
	}
}
