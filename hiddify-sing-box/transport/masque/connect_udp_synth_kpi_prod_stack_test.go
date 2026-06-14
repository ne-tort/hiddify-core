package masque

// GATE-CONNECT-UDP-SYNTH: prod profile unlimited up/down on instant link; DoD 200+, synth target 500+.

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

func benchConnectUDPProdProfileH3Download(
	t *testing.T,
	link datagramTransportLink,
	duration time.Duration,
	payloadLen int,
) (int64, float64, error) {
	t.Helper()
	if payloadLen <= 0 {
		payloadLen = connectudp.DefaultBenchUDPPayloadLen
	}
	fountain := runUDPEcho(t, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	echoAddr := fountain.LocalAddr().(*net.UDPAddr)

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

	pkt, err := session.ListenPacket(waitCtx, M.Socksaddr{
		Addr: netip.MustParseAddr(echoAddr.IP.String()),
		Port: uint16(echoAddr.Port),
	})
	if err != nil {
		return 0, 0, err
	}
	defer func() { _ = pkt.Close() }()

	return benchConnectUDPPacketDownloadViaEcho(pkt, echoAddr, duration, payloadLen)
}

func benchConnectUDPProdProfileH2Download(
	t *testing.T,
	link h2TransportLink,
	duration time.Duration,
	payloadLen int,
) (int64, float64, error) {
	t.Helper()
	if payloadLen <= 0 {
		payloadLen = connectudp.DefaultBenchUDPPayloadLen
	}
	fountain := runUDPEcho(t, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	echoAddr := fountain.LocalAddr().(*net.UDPAddr)

	proxyPort := startInProcessH2UDPConnectProxy(t)
	session, waitCtx := newConnectUDPProdProfileH2SessionWithLink(t, proxyPort, link)

	pkt, err := session.ListenPacket(waitCtx, M.Socksaddr{
		Addr: netip.MustParseAddr(echoAddr.IP.String()),
		Port: uint16(echoAddr.Port),
	})
	if err != nil {
		return 0, 0, err
	}
	defer func() { _ = pkt.Close() }()

	return benchConnectUDPPacketDownloadViaEcho(pkt, echoAddr, duration, payloadLen)
}

func benchConnectUDPPacketDownloadViaEcho(
	pkt net.PacketConn,
	echoAddr *net.UDPAddr,
	duration time.Duration,
	payloadLen int,
) (int64, float64, error) {
	payload := make([]byte, payloadLen)
	for i := range payload {
		payload[i] = byte(i % 251)
	}
	buf := make([]byte, payloadLen+64)
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		for {
			select {
			case <-stop:
				return
			default:
				_ = pkt.SetWriteDeadline(time.Now().Add(2 * time.Second))
				if _, err := pkt.WriteTo(payload, echoAddr); err != nil {
					return
				}
			}
		}
	}()

	deadline := time.Now().Add(duration)
	var received int64
	for time.Now().Before(deadline) {
		_ = pkt.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, _, err := pkt.ReadFrom(buf)
		if err != nil {
			if received > 0 {
				break
			}
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			return 0, 0, err
		}
		received += int64(n)
	}
	secs := duration.Seconds()
	if secs <= 0 {
		secs = 1
	}
	return received, float64(received*8) / secs / 1e6, nil
}

func assertConnectUDPSynthInstantMbps(t *testing.T, layer, leg string, mbps float64, hint string) {
	t.Helper()
	if mbps < connectUDPSynthInstantMinMbps {
		t.Fatalf("%s", synthKPIDiagnostic(layer, leg, mbps, connectUDPSynthInstantMinMbps,
			hint+"; prod DoD min "+formatSynthMbps(connectUDPSynthProdMinMbps)+" Mbit/s each leg"))
	}
}

func assertConnectUDPSynthAsymmetry(t *testing.T, upMbps, downMbps float64) {
	t.Helper()
	minLeg := upMbps
	maxLeg := downMbps
	if downMbps < minLeg {
		minLeg = downMbps
		maxLeg = upMbps
	}
	if minLeg < connectUDPSynthInstantMinMbps {
		t.Fatalf("%s", synthKPIDiagnostic("L4 connect-udp prod", "min(up,down)", minLeg, connectUDPSynthInstantMinMbps,
			"instant-link synth legs"))
	}
	if minLeg <= 0 {
		t.Fatal("connect-udp asymmetry: min leg is zero")
	}
	ratio := maxLeg / minLeg
	if ratio > connectUDPSynthAsymmetryMaxRatio {
		t.Fatalf("L4 connect-udp prod asymmetry: up=%s down=%s ratio=%.2f (want <= %.1f)",
			formatSynthMbps(upMbps), formatSynthMbps(downMbps), ratio, connectUDPSynthAsymmetryMaxRatio)
	}
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

type connectUDPProdDownloadHandle struct {
	pkt      net.PacketConn
	echoAddr *net.UDPAddr
	cleanup  func()
}

func startConnectUDPProdH3DownloadHandle(tb testing.TB) *connectUDPProdDownloadHandle {
	tb.Helper()
	echo := runUDPEcho(tb, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	echoAddr := echo.LocalAddr().(*net.UDPAddr)

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
		tb.Fatalf("connect-udp-h3 download handle: %v", err)
	}
	pkt, err := session.ListenPacket(waitCtx, M.Socksaddr{
		Addr: netip.MustParseAddr(echoAddr.IP.String()),
		Port: uint16(echoAddr.Port),
	})
	if err != nil {
		_ = session.Close()
		cancel()
		tb.Fatalf("ListenPacket connect-udp-h3 download: %v", err)
	}
	return &connectUDPProdDownloadHandle{
		pkt:      pkt,
		echoAddr: echoAddr,
		cleanup: func() {
			_ = pkt.Close()
			_ = session.Close()
			cancel()
		},
	}
}

func startConnectUDPProdH2DownloadHandle(tb testing.TB) *connectUDPProdDownloadHandle {
	tb.Helper()
	echo := runUDPEcho(tb, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	echoAddr := echo.LocalAddr().(*net.UDPAddr)

	proxyPort := startInProcessH2UDPConnectProxy(tb)
	session, waitCtx := newConnectUDPProdProfileH2SessionWithLinkTB(tb, proxyPort, instantH2Link{})
	pkt, err := session.ListenPacket(waitCtx, M.Socksaddr{
		Addr: netip.MustParseAddr(echoAddr.IP.String()),
		Port: uint16(echoAddr.Port),
	})
	if err != nil {
		tb.Fatalf("ListenPacket connect-udp-h2 download: %v", err)
	}
	return &connectUDPProdDownloadHandle{
		pkt:      pkt,
		echoAddr: echoAddr,
		cleanup: func() {
			_ = pkt.Close()
			_ = session.Close()
		},
	}
}

func (h *connectUDPProdDownloadHandle) close() {
	if h != nil && h.cleanup != nil {
		h.cleanup()
	}
}

func (h *connectUDPProdDownloadHandle) downloadOnce(nbytes int64) (int64, error) {
	payload := make([]byte, connectudp.DefaultBenchUDPPayloadLen)
	for i := range payload {
		payload[i] = byte(i % 251)
	}
	buf := make([]byte, len(payload)+64)
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		for {
			select {
			case <-stop:
				return
			default:
				_ = h.pkt.SetWriteDeadline(time.Now().Add(5 * time.Second))
				if _, err := h.pkt.WriteTo(payload, h.echoAddr); err != nil {
					return
				}
			}
		}
	}()
	var received int64
	for received < nbytes {
		_ = h.pkt.SetReadDeadline(time.Now().Add(5 * time.Second))
		n, _, err := h.pkt.ReadFrom(buf)
		if err != nil {
			return received, err
		}
		received += int64(n)
	}
	return received, nil
}

// TestGATEConnectUDPH3SynthProdUpload locks connect-udp-h3 prod unlimited upload on instant link (synth >= 500 Mbit/s).
func TestGATEConnectUDPH3SynthProdUpload(t *testing.T) {
	dur := connectUDPSynthProdBenchDuration
	bytes, mbps, err := benchConnectUDPProdProfileH3Upload(t, instantDatagramLink{}, dur, 0, connectudp.DefaultBenchUDPPayloadLen)
	if err != nil {
		t.Fatalf("connect-udp-h3 prod upload: %v", err)
	}
	t.Logf("GATE-CONNECT-UDP-SYNTH h3 upload: %.1f Mbit/s (%d bytes)", mbps, bytes)
	assertConnectUDPSynthInstantMbps(t, "L4 connect-udp-h3 prod", "udp_up", mbps,
		"instant QUIC datagram path — check split/window/scheduler")
}

// TestGATEConnectUDPH3SynthProdDownload locks connect-udp-h3 prod unlimited download on instant link (synth >= 500 Mbit/s).
func TestGATEConnectUDPH3SynthProdDownload(t *testing.T) {
	dur := connectUDPSynthProdBenchDuration
	bytes, mbps, err := benchConnectUDPProdProfileH3Download(t, instantDatagramLink{}, dur, connectudp.DefaultBenchUDPPayloadLen)
	if err != nil {
		t.Fatalf("connect-udp-h3 prod download: %v", err)
	}
	t.Logf("GATE-CONNECT-UDP-SYNTH h3 download: %.1f Mbit/s (%d bytes)", mbps, bytes)
	assertConnectUDPSynthInstantMbps(t, "L4 connect-udp-h3 prod", "udp_down", mbps,
		"S2C datagram receive — check QUIC datagram FC / relay")
}

// TestGATEConnectUDPH2SynthProdUpload locks connect-udp-h2 prod unlimited upload on instant link (synth >= 500 Mbit/s).
func TestGATEConnectUDPH2SynthProdUpload(t *testing.T) {
	dur := connectUDPSynthProdBenchDuration
	bytes, mbps, err := benchConnectUDPProdProfileH2Upload(t, instantH2Link{}, dur, 0, connectudp.DefaultBenchUDPPayloadLen)
	if err != nil {
		t.Fatalf("connect-udp-h2 prod upload: %v", err)
	}
	t.Logf("GATE-CONNECT-UDP-SYNTH h2 upload: %.1f Mbit/s (%d bytes)", mbps, bytes)
	assertConnectUDPSynthInstantMbps(t, "L4 connect-udp-h2 prod", "udp_up", mbps,
		"H2 capsule path — check DatagramSplitConn / flush / relay")
}

// TestGATEConnectUDPH2SynthProdDownload locks connect-udp-h2 prod unlimited download on instant link (synth >= 500 Mbit/s).
func TestGATEConnectUDPH2SynthProdDownload(t *testing.T) {
	dur := connectUDPSynthProdBenchDuration
	bytes, mbps, err := benchConnectUDPProdProfileH2Download(t, instantH2Link{}, dur, connectudp.DefaultBenchUDPPayloadLen)
	if err != nil {
		t.Fatalf("connect-udp-h2 prod download: %v", err)
	}
	t.Logf("GATE-CONNECT-UDP-SYNTH h2 download: %.1f Mbit/s (%d bytes)", mbps, bytes)
	assertConnectUDPSynthInstantMbps(t, "L4 connect-udp-h2 prod", "udp_down", mbps,
		"H2 capsule S2C — check capsule read / relay")
}

// TestGATEConnectUDPPairedSynthUpload ensures H3 upload is not materially behind H2 on prod profile.
func TestGATEConnectUDPPairedSynthUpload(t *testing.T) {
	dur := connectUDPSynthProdBenchDuration
	_, h2Mbps, err := benchConnectUDPProdProfileH2Upload(t, instantH2Link{}, dur, 0, connectudp.DefaultBenchUDPPayloadLen)
	if err != nil {
		t.Fatalf("connect-udp-h2 prod upload (paired): %v", err)
	}
	_, h3Mbps, err := benchConnectUDPProdProfileH3Upload(t, instantDatagramLink{}, dur, 0, connectudp.DefaultBenchUDPPayloadLen)
	if err != nil {
		t.Fatalf("connect-udp-h3 prod upload (paired): %v", err)
	}
	ratio := h3Mbps / h2Mbps
	t.Logf("GATE-CONNECT-UDP-SYNTH paired upload: H2=%.1f H3=%.1f ratio=%.2f", h2Mbps, h3Mbps, ratio)
	assertConnectUDPSynthInstantMbps(t, "L4 connect-udp-h3 prod", "udp_up", h3Mbps, "paired with H2 upload")
	assertConnectUDPSynthInstantMbps(t, "L4 connect-udp-h2 prod", "udp_up", h2Mbps, "paired with H3 upload")
	if ratio < connectUDPSynthParityMinRatio {
		t.Fatal(synthKPIDiagnostic("L4 connect-udp paired", "H3/H2 upload ratio", ratio, connectUDPSynthParityMinRatio,
			"H3 must stay within 15% of H2 upload on prod profile"))
	}
}

// TestGATEConnectUDPSynthProdAsymmetryH3 locks min(up,down) >= 500 and up/down ratio <= 4 on instant link.
func TestGATEConnectUDPSynthProdAsymmetryH3(t *testing.T) {
	dur := connectUDPSynthProdBenchDuration
	_, upMbps, err := benchConnectUDPProdProfileH3Upload(t, instantDatagramLink{}, dur, 0, connectudp.DefaultBenchUDPPayloadLen)
	if err != nil {
		t.Fatalf("connect-udp-h3 prod upload (asymmetry): %v", err)
	}
	_, downMbps, err := benchConnectUDPProdProfileH3Download(t, instantDatagramLink{}, dur, connectudp.DefaultBenchUDPPayloadLen)
	if err != nil {
		t.Fatalf("connect-udp-h3 prod download (asymmetry): %v", err)
	}
	t.Logf("GATE-CONNECT-UDP-SYNTH h3 asymmetry: up=%.1f down=%.1f", upMbps, downMbps)
	assertConnectUDPSynthAsymmetry(t, upMbps, downMbps)
}
