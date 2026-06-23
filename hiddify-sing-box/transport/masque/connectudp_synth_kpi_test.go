package masque

// GATE-CONNECT-UDP-SYNTH: prod profile unlimited up/down on instant link; DoD 200+, synth target 500+.

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"runtime"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/transport/masque/connectudp"
	h2c "github.com/sagernet/sing-box/transport/masque/h2"
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

	return benchConnectUDPPacketUpload(t, pkt, sinkAddr, duration, targetMbit, payloadLen)
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

	return benchConnectUDPPacketUpload(t, pkt, sinkAddr, duration, targetMbit, payloadLen)
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

	return benchConnectUDPPacketDownloadViaEcho(t, pkt, echoAddr, duration, payloadLen)
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

	return benchConnectUDPPacketDownloadViaEcho(t, pkt, echoAddr, duration, payloadLen)
}

func benchConnectUDPPacketDownloadViaEcho(
	tb testing.TB,
	pkt net.PacketConn,
	echoAddr *net.UDPAddr,
	duration time.Duration,
	payloadLen int,
) (int64, float64, error) {
	tb.Helper()
	payload := make([]byte, payloadLen)
	for i := range payload {
		payload[i] = byte(i % 251)
	}
	buf := make([]byte, payloadLen+64)
	var inFlight atomic.Int32
	for i := 0; i < connectUDPEchoDownloadPrimeDepth; i++ {
		if _, err := pkt.WriteTo(payload, echoAddr); err != nil {
			return 0, 0, err
		}
		inFlight.Add(1)
	}
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		for {
			select {
			case <-stop:
				return
			default:
			}
			for inFlight.Load() >= int32(connectUDPEchoDownloadPrimeDepth) {
				runtime.Gosched()
			}
			if _, err := pkt.WriteTo(payload, echoAddr); err != nil {
				return
			}
			inFlight.Add(1)
		}
	}()

	deadline := time.Now().Add(duration)
	wall := connectUDPSynthBenchWallDeadline(duration)
	var received int64
	for time.Now().Before(deadline) {
		if time.Now().After(wall) {
			break
		}
		n, _, err := readFromWithStallGuard(tb, pkt, buf, connectUDPSynthUploadWriteStall)
		if err != nil {
			if received > 0 {
				break
			}
			return 0, 0, err
		}
		received += int64(n)
		inFlight.Add(-1)
	}
	secs := duration.Seconds()
	if secs <= 0 {
		secs = 1
	}
	return received, float64(received*8) / secs / 1e6, nil
}

// benchConnectUDPPacketDownloadPipelined measures S2C receive with bounded in-flight echo
// requests. pipeline=0 uses unlimited background WriteTo (GATE echo-duplex shape).
func benchConnectUDPPacketDownloadPipelined(
	tb testing.TB,
	pkt net.PacketConn,
	echoAddr *net.UDPAddr,
	duration time.Duration,
	payloadLen int,
	pipeline int,
) (int64, float64, error) {
	tb.Helper()
	if pipeline <= 0 {
		return benchConnectUDPPacketDownloadViaEcho(tb, pkt, echoAddr, duration, payloadLen)
	}
	payload := make([]byte, payloadLen)
	for i := range payload {
		payload[i] = byte(i % 251)
	}
	buf := make([]byte, payloadLen+64)
	for i := 0; i < pipeline; i++ {
		if _, err := pkt.WriteTo(payload, echoAddr); err != nil {
			return 0, 0, err
		}
	}
	deadline := time.Now().Add(duration)
	wall := connectUDPSynthBenchWallDeadline(duration)
	var received int64
	for time.Now().Before(deadline) {
		if time.Now().After(wall) {
			break
		}
		n, _, err := readFromWithStallGuard(tb, pkt, buf, connectUDPSynthUploadWriteStall)
		if err != nil {
			if received > 0 {
				break
			}
			return 0, 0, err
		}
		received += int64(n)
		if _, err := pkt.WriteTo(payload, echoAddr); err != nil {
			break
		}
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
	tb.Cleanup(func() { closeConnectUDPTestSession(session) })
	return session, waitCtx
}

func benchConnectUDPPacketUpload(
	tb testing.TB,
	pkt net.PacketConn,
	sinkAddr *net.UDPAddr,
	duration time.Duration,
	targetMbit float64,
	payloadLen int,
) (int64, float64, error) {
	tb.Helper()
	payload := make([]byte, payloadLen)
	for i := range payload {
		payload[i] = byte(i % 251)
	}
	deadline := time.Now().Add(duration)
	wall := connectUDPSynthBenchWallDeadline(duration)
	var paceSlot time.Time
	var sent int64
	for time.Now().Before(deadline) {
		if time.Now().After(wall) {
			break
		}
		if err := writeToWithStallGuard(tb, pkt, payload, sinkAddr, connectUDPSynthUploadWriteStall); err != nil {
			if sent > 0 {
				break
			}
			return 0, 0, err
		}
		sent += int64(len(payload))
		connectudp.PaceSleepUntil(&paceSlot, payloadLen, targetMbit)
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

// TestGATEConnectUDPH3SynthProdDownload locks echo-duplex download (bg WriteTo + fg ReadFrom) — stress gate.
func TestGATEConnectUDPH3SynthProdDownload(t *testing.T) {
	dur := connectUDPSynthProdBenchDuration
	bytes, mbps, err := benchConnectUDPProdProfileH3Download(t, instantDatagramLink{}, dur, connectudp.DefaultBenchUDPPayloadLen)
	if err != nil {
		t.Fatalf("connect-udp-h3 prod download: %v", err)
	}
	t.Logf("GATE-CONNECT-UDP-SYNTH h3 download: %.1f Mbit/s (%d bytes)", mbps, bytes)
	assertConnectUDPSynthInstantMbps(t, "L4 connect-udp-h3 prod", "udp_down", mbps,
		"echo-duplex C2S/S2C contention — see TestLocalizeConnectUDPH3DownloadPipelineDepth")
}

// TestGATEConnectUDPH3SynthProdDownloadFountain locks S2C-only download (server UDP flood after prime).
func TestGATEConnectUDPH3SynthProdDownloadFountain(t *testing.T) {
	dur := connectUDPSynthProdBenchDuration
	fountain := startUDPFountain(t, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	fountainAddr := fountain.LocalAddr().(*net.UDPAddr)
	proxyPort := startInProcessMasqueUDPProxy(t, func(mux *http.ServeMux, proxyPort int) {
		registerMasqueUDPProxyHandler(t, mux, proxyPort)
	})
	waitCtx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	session, err := (CoreClientFactory{}).NewSession(waitCtx, ClientOptions{
		Server:              "127.0.0.1",
		ServerPort:          uint16(proxyPort),
		TransportMode:       option.MasqueTransportModeConnectUDP,
		MasqueQUICCryptoTLS: &tls.Config{InsecureSkipVerify: true},
	})
	if err != nil {
		t.Fatalf("session: %v", err)
	}
	defer func() { _ = session.Close() }()
	pkt, err := session.ListenPacket(waitCtx, M.Socksaddr{
		Addr: netip.MustParseAddr(fountainAddr.IP.String()),
		Port: uint16(fountainAddr.Port),
	})
	if err != nil {
		t.Fatalf("ListenPacket: %v", err)
	}
	defer func() { _ = pkt.Close() }()
	primeUDPBench(t, pkt, fountainAddr)
	bytes, mbps, err := benchConnectUDPPacketReceiveOnly(t, pkt, dur, connectudp.DefaultBenchUDPPayloadLen)
	if err != nil {
		t.Fatalf("fountain download: %v", err)
	}
	t.Logf("GATE-CONNECT-UDP-SYNTH h3 download-fountain: %.1f Mbit/s (%d bytes)", mbps, bytes)
	assertConnectUDPSynthInstantMbps(t, "L4 connect-udp-h3 prod", "udp_down_fountain", mbps,
		"S2C-only receive path")
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

// TestLocalizeConnectUDPH2UploadMaxCapsule logs upload at max RFC9297 DATAGRAM payload.
// FAIL when path ceiling is clearly below DoD track (~650+ Mbit/s on instant link; prior good run ~750).
func TestLocalizeConnectUDPH2UploadMaxCapsule(t *testing.T) {
	dur := connectUDPSynthProdBenchDuration
	maxPayload := h2c.MaxUDPPayloadPerDatagramCapsule()
	bytes, mbps, err := benchConnectUDPProdProfileH2Upload(t, instantH2Link{}, dur, 0, maxPayload)
	if err != nil {
		t.Fatalf("connect-udp-h2 upload max capsule: %v", err)
	}
	t.Logf("LOCALIZE h2 upload maxCapsule(%dB): %.1f Mbit/s (%d bytes)", maxPayload, mbps, bytes)
	const maxCapsulePathMinMbps = 650.0
	if mbps < maxCapsulePathMinMbps {
		t.Fatalf("h2 upload max capsule %.1f Mbit/s < %.0f — wire path below DoD track (512 B structural is separate)",
			mbps, maxCapsulePathMinMbps)
	}
}

// TestLocalizeConnectUDPH2UploadMaxCapsuleDirectDial separates max-capsule wire ceiling from
// session/DatagramSplitConn wrapper overhead (FAIL when direct >> listen). ListenPacket first.
func TestLocalizeConnectUDPH2UploadMaxCapsuleDirectDial(t *testing.T) {
	dur := connectUDPSynthProdBenchDuration
	maxPayload := h2c.MaxUDPPayloadPerDatagramCapsule()
	_, listenMbps, err := benchConnectUDPProdProfileH2Upload(t, instantH2Link{}, dur, 0, maxPayload)
	if err != nil {
		t.Fatalf("h2 ListenPacket max capsule: %v", err)
	}
	_, directMbps, err := benchConnectUDPH2OverlayDirectUpload(t, instantH2Link{}, dur, maxPayload)
	if err != nil {
		t.Fatalf("h2 overlay direct max capsule: %v", err)
	}
	ratio := directMbps / listenMbps
	t.Logf("LOCALIZE h2 maxCapsule(%dB) direct vs listen: direct=%.1f listen=%.1f ratio=%.2f",
		maxPayload, directMbps, listenMbps, ratio)
	if directMbps >= 700 && listenMbps < 0.75*directMbps {
		t.Fatalf("maxCapsule session wrapper bottleneck listen=%.1f direct=%.1f (<75%% of wire path)",
			listenMbps, directMbps)
	}
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

// TestLocalizeConnectUDPH3DuplexEcho logs upload-only vs echo-duplex download on instant link.
// Localization only — does not FAIL on OPEN ceiling; use to confirm C2S echo contention vs upload-only.
func TestLocalizeConnectUDPH3DuplexEcho(t *testing.T) {
	dur := connectUDPSynthProdBenchDuration
	_, upMbps, err := benchConnectUDPProdProfileH3Upload(t, instantDatagramLink{}, dur, 0, connectudp.DefaultBenchUDPPayloadLen)
	if err != nil {
		t.Fatalf("upload leg: %v", err)
	}
	_, downMbps, err := benchConnectUDPProdProfileH3Download(t, instantDatagramLink{}, dur, connectudp.DefaultBenchUDPPayloadLen)
	if err != nil {
		t.Fatalf("echo-duplex download leg: %v", err)
	}
	ratio := upMbps / downMbps
	t.Logf("LOCALIZE connect-udp-h3: upload-only=%.1f echo-duplex-down=%.1f up/down=%.2f", upMbps, downMbps, ratio)
	if downMbps < connectUDPSynthInstantMinMbps {
		t.Logf("OPEN: echo-duplex download below synth gate %.0f Mbit/s — shared QUIC conn C2S echo vs S2C receive", connectUDPSynthInstantMinMbps)
	}
	if ratio > 2.0 {
		t.Logf("OPEN: upload-only >> echo-duplex-down (ratio %.2f) — contention signature", ratio)
	}
}

// TestLocalizeConnectUDPH3DownloadPipelineDepth logs download Mbps vs in-flight echo depth.
// Localization only — separates unbounded C2S flood contention from S2C receive ceiling.
func TestLocalizeConnectUDPH3DownloadPipelineDepth(t *testing.T) {
	dur := connectUDPSynthProdBenchDuration
	echo := runUDPEcho(t, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	echoAddr := echo.LocalAddr().(*net.UDPAddr)
	proxyPort := startInProcessMasqueUDPProxy(t, func(mux *http.ServeMux, proxyPort int) {
		registerMasqueUDPProxyHandler(t, mux, proxyPort)
	})
	waitCtx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	session, err := (CoreClientFactory{}).NewSession(waitCtx, ClientOptions{
		Server:              "127.0.0.1",
		ServerPort:          uint16(proxyPort),
		TransportMode:       option.MasqueTransportModeConnectUDP,
		MasqueQUICCryptoTLS: &tls.Config{InsecureSkipVerify: true},
	})
	if err != nil {
		t.Fatalf("session: %v", err)
	}
	defer func() { _ = session.Close() }()
	pkt, err := session.ListenPacket(waitCtx, M.Socksaddr{
		Addr: netip.MustParseAddr(echoAddr.IP.String()),
		Port: uint16(echoAddr.Port),
	})
	if err != nil {
		t.Fatalf("ListenPacket: %v", err)
	}
	defer func() { _ = pkt.Close() }()

	payloadLen := connectudp.DefaultBenchUDPPayloadLen
	for _, depth := range []int{1, 8, 64, 128, 256, 0} {
		label := "unlimited"
		if depth > 0 {
			label = fmt.Sprintf("pipeline=%d", depth)
		}
		_, mbps, err := benchConnectUDPPacketDownloadPipelined(t, pkt, echoAddr, dur, payloadLen, depth)
		if err != nil {
			t.Fatalf("%s: %v", label, err)
		}
		t.Logf("LOCALIZE connect-udp-h3 download %s: %.1f Mbit/s", label, mbps)
	}
}

func startUDPFountain(tb testing.TB, laddr *net.UDPAddr) *net.UDPConn {
	tb.Helper()
	conn, err := net.ListenUDP("udp", laddr)
	if err != nil {
		tb.Fatalf("ListenUDP fountain: %v", err)
	}
	tb.Cleanup(func() { _ = conn.Close() })
	go func() {
		buf := make([]byte, 2048)
		payload := make([]byte, connectudp.DefaultBenchUDPPayloadLen)
		var blastAddr *net.UDPAddr
		blast := false
		for {
			n, addr, err := conn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			if n <= 0 || blast {
				continue
			}
			blastAddr = addr
			blast = true
			tuneUDPFountainSocket(conn)
			go func() {
				for {
					_, err := conn.WriteToUDP(payload, blastAddr)
					if err != nil {
						return
					}
				}
			}()
		}
	}()
	return conn
}

func tuneUDPFountainSocket(conn *net.UDPConn) {
	const buf = 4 << 20
	_ = conn.SetWriteBuffer(buf)
}

func benchConnectUDPPacketReceiveOnly(tb testing.TB, pkt net.PacketConn, duration time.Duration, payloadLen int) (int64, float64, error) {
	tb.Helper()
	buf := make([]byte, payloadLen+64)
	deadline := time.Now().Add(duration)
	wall := connectUDPSynthBenchWallDeadline(duration)
	var received int64
	for time.Now().Before(deadline) {
		if time.Now().After(wall) {
			break
		}
		n, _, err := readFromWithStallGuard(tb, pkt, buf, connectUDPSynthUploadWriteStall)
		if err != nil {
			if received > 0 {
				break
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

// TestLocalizeConnectUDPH3DownloadFountain logs S2C-only receive (server UDP flood after prime).
func TestLocalizeConnectUDPH3DownloadFountain(t *testing.T) {
	dur := connectUDPSynthProdBenchDuration
	fountain := startUDPFountain(t, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	fountainAddr := fountain.LocalAddr().(*net.UDPAddr)
	proxyPort := startInProcessMasqueUDPProxy(t, func(mux *http.ServeMux, proxyPort int) {
		registerMasqueUDPProxyHandler(t, mux, proxyPort)
	})
	waitCtx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	session, err := (CoreClientFactory{}).NewSession(waitCtx, ClientOptions{
		Server:              "127.0.0.1",
		ServerPort:          uint16(proxyPort),
		TransportMode:       option.MasqueTransportModeConnectUDP,
		MasqueQUICCryptoTLS: &tls.Config{InsecureSkipVerify: true},
	})
	if err != nil {
		t.Fatalf("session: %v", err)
	}
	defer func() { _ = session.Close() }()
	pkt, err := session.ListenPacket(waitCtx, M.Socksaddr{
		Addr: netip.MustParseAddr(fountainAddr.IP.String()),
		Port: uint16(fountainAddr.Port),
	})
	if err != nil {
		t.Fatalf("ListenPacket: %v", err)
	}
	defer func() { _ = pkt.Close() }()
	primeUDPBench(t, pkt, fountainAddr)
	_, mbps, err := benchConnectUDPPacketReceiveOnly(t, pkt, dur, connectudp.DefaultBenchUDPPayloadLen)
	if err != nil {
		t.Fatalf("receive-only: %v", err)
	}
	t.Logf("LOCALIZE connect-udp-h3 download fountain-flood (S2C-only): %.1f Mbit/s", mbps)
	if mbps < connectUDPSynthInstantMinMbps {
		t.Logf("OPEN: S2C-only below synth gate — receive/datagram path ceiling, not echo contention")
	}
}

// TestLocalizeConnectUDPH3EchoDuplexGap compares echo-duplex vs fountain S2C on H3.
// Separate sessions per leg — reuse after Close() yields false echo=0 gap.
func TestLocalizeConnectUDPH3EchoDuplexGap(t *testing.T) {
	dur := connectUDPSynthProdBenchDuration
	fountain := startUDPFountain(t, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	fountainAddr := fountain.LocalAddr().(*net.UDPAddr)
	echo := runUDPEcho(t, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	echoAddr := echo.LocalAddr().(*net.UDPAddr)

	openSession := func() (ClientSession, context.Context) {
		proxyPort := startInProcessMasqueUDPProxy(t, func(mux *http.ServeMux, proxyPort int) {
			registerMasqueUDPProxyHandler(t, mux, proxyPort)
		})
		waitCtx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
		t.Cleanup(cancel)
		session, err := (CoreClientFactory{}).NewSession(waitCtx, ClientOptions{
			Server:              "127.0.0.1",
			ServerPort:          uint16(proxyPort),
			TransportMode:       option.MasqueTransportModeConnectUDP,
			MasqueQUICCryptoTLS: &tls.Config{InsecureSkipVerify: true},
		})
		if err != nil {
			t.Fatalf("session: %v", err)
		}
		t.Cleanup(func() { _ = session.Close() })
		return session, waitCtx
	}

	fountainSession, fountainCtx := openSession()
	fountainPkt, err := fountainSession.ListenPacket(fountainCtx, M.Socksaddr{
		Addr: netip.MustParseAddr(fountainAddr.IP.String()),
		Port: uint16(fountainAddr.Port),
	})
	if err != nil {
		t.Fatalf("ListenPacket fountain: %v", err)
	}
	primeUDPBench(t, fountainPkt, fountainAddr)
	_, fountainMbps, err := benchConnectUDPPacketReceiveOnly(t, fountainPkt, dur, connectudp.DefaultBenchUDPPayloadLen)
	_ = fountainPkt.Close()
	if err != nil {
		t.Fatalf("fountain receive: %v", err)
	}

	echoSession, echoCtx := openSession()
	echoPkt, err := echoSession.ListenPacket(echoCtx, M.Socksaddr{
		Addr: netip.MustParseAddr(echoAddr.IP.String()),
		Port: uint16(echoAddr.Port),
	})
	if err != nil {
		t.Fatalf("ListenPacket echo: %v", err)
	}
	defer func() { _ = echoPkt.Close() }()
	_, echoMbps, err := benchConnectUDPPacketDownloadViaEcho(t, echoPkt, echoAddr, dur, connectudp.DefaultBenchUDPPayloadLen)
	if err != nil {
		t.Fatalf("echo-duplex download: %v", err)
	}

	ratio := echoMbps / fountainMbps
	t.Logf("LOCALIZE echo-duplex gap: fountain=%.1f echo=%.1f ratio=%.2f (want ratio>=0.75 when fountain>=400)",
		fountainMbps, echoMbps, ratio)
	if fountainMbps >= 400 && ratio < 0.75 {
		t.Fatalf("echo-duplex %.1f Mbit/s < 75%% of fountain %.1f — structural C2S/S2C contention on DATAGRAM plane", echoMbps, fountainMbps)
	}
}

// TestLocalizeConnectUDPH2EchoDuplexGap compares H2 echo-duplex vs upload-only on the same host.
func TestLocalizeConnectUDPH2EchoDuplexGap(t *testing.T) {
	dur := connectUDPSynthProdBenchDuration
	_, uploadMbps, err := benchConnectUDPProdProfileH2Upload(t, instantH2Link{}, dur, 0, connectudp.DefaultBenchUDPPayloadLen)
	if err != nil {
		t.Fatalf("h2 upload-only: %v", err)
	}
	_, echoMbps, err := benchConnectUDPProdProfileH2Download(t, instantH2Link{}, dur, connectudp.DefaultBenchUDPPayloadLen)
	if err != nil {
		t.Fatalf("h2 echo-duplex download: %v", err)
	}
	ratio := echoMbps / uploadMbps
	t.Logf("LOCALIZE h2 echo-duplex gap: upload-only=%.1f echo-down=%.1f ratio=%.2f (want ratio>=0.75 when upload>=400)",
		uploadMbps, echoMbps, ratio)
	if uploadMbps >= 400 && ratio < 0.75 {
		t.Fatalf("h2 echo-duplex %.1f Mbit/s < 75%% of upload-only %.1f — capsule duplex contention", echoMbps, uploadMbps)
	}
}

// TestLocalizeConnectUDPH2DownloadPipelineDepth logs echo-duplex download vs in-flight C2S depth (H2).
func TestLocalizeConnectUDPH2DownloadPipelineDepth(t *testing.T) {
	dur := connectUDPSynthProdBenchDuration
	echo := runUDPEcho(t, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	echoAddr := echo.LocalAddr().(*net.UDPAddr)
	proxyPort := startInProcessH2UDPConnectProxy(t)
	session, waitCtx := newConnectUDPProdProfileH2SessionWithLink(t, proxyPort, instantH2Link{})
	pkt, err := session.ListenPacket(waitCtx, M.Socksaddr{
		Addr: netip.MustParseAddr(echoAddr.IP.String()),
		Port: uint16(echoAddr.Port),
	})
	if err != nil {
		t.Fatalf("ListenPacket: %v", err)
	}
	defer func() { _ = pkt.Close() }()
	payloadLen := connectudp.DefaultBenchUDPPayloadLen
	for _, depth := range []int{1, 8, 64, 128, 256, 0} {
		label := "unlimited"
		if depth > 0 {
			label = fmt.Sprintf("pipeline=%d", depth)
		}
		_, mbps, err := benchConnectUDPPacketDownloadPipelined(t, pkt, echoAddr, dur, payloadLen, depth)
		if err != nil {
			t.Fatalf("%s: %v", label, err)
		}
		t.Logf("LOCALIZE connect-udp-h2 download %s: %.1f Mbit/s", label, mbps)
	}
}

// TestLocalizeConnectUDPH3Pipeline1ProdShape locks TUN read→write echo on H3 DATAGRAM plane.
func TestLocalizeConnectUDPH3Pipeline1ProdShape(t *testing.T) {
	dur := connectUDPSynthProdBenchDuration
	echo := runUDPEcho(t, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	echoAddr := echo.LocalAddr().(*net.UDPAddr)
	proxyPort := startInProcessMasqueUDPProxy(t, func(mux *http.ServeMux, proxyPort int) {
		registerMasqueUDPProxyHandler(t, mux, proxyPort)
	})
	waitCtx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	session, err := (CoreClientFactory{}).NewSession(waitCtx, ClientOptions{
		Server:              "127.0.0.1",
		ServerPort:          uint16(proxyPort),
		TransportMode:       option.MasqueTransportModeConnectUDP,
		MasqueQUICCryptoTLS: &tls.Config{InsecureSkipVerify: true},
	})
	if err != nil {
		t.Fatalf("session: %v", err)
	}
	defer func() { _ = session.Close() }()
	pkt, err := session.ListenPacket(waitCtx, M.Socksaddr{
		Addr: netip.MustParseAddr(echoAddr.IP.String()),
		Port: uint16(echoAddr.Port),
	})
	if err != nil {
		t.Fatalf("ListenPacket: %v", err)
	}
	defer func() { _ = pkt.Close() }()
	_, mbps, err := benchConnectUDPPacketDownloadPipelined(t, pkt, echoAddr, dur, connectudp.DefaultBenchUDPPayloadLen, 1)
	if err != nil {
		t.Fatalf("pipeline=1: %v", err)
	}
	t.Logf("LOCALIZE h3 pipeline=1 prod-shape: %.1f Mbit/s", mbps)
	const pipeline1MinMbps = 50.0
	if mbps < pipeline1MinMbps {
		t.Fatalf("h3 pipeline=1 prod-shape %.1f Mbit/s < %.0f — interactive echo/TUN path OPEN", mbps, pipeline1MinMbps)
	}
}

// TestLocalizeConnectUDPH2Pipeline1ProdShape locks TUN read→write echo (pipeline depth 1).
// FAIL below threshold — 2 ms coalesce on both legs capped this near ~2 Mbit/s before adaptive downlink.
func TestLocalizeConnectUDPH2Pipeline1ProdShape(t *testing.T) {
	dur := connectUDPSynthProdBenchDuration
	echo := runUDPEcho(t, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	echoAddr := echo.LocalAddr().(*net.UDPAddr)
	proxyPort := startInProcessH2UDPConnectProxy(t)
	session, waitCtx := newConnectUDPProdProfileH2SessionWithLink(t, proxyPort, instantH2Link{})
	pkt, err := session.ListenPacket(waitCtx, M.Socksaddr{
		Addr: netip.MustParseAddr(echoAddr.IP.String()),
		Port: uint16(echoAddr.Port),
	})
	if err != nil {
		t.Fatalf("ListenPacket: %v", err)
	}
	defer func() { _ = pkt.Close() }()
	_, mbps, err := benchConnectUDPPacketDownloadPipelined(t, pkt, echoAddr, dur, connectudp.DefaultBenchUDPPayloadLen, 1)
	if err != nil {
		t.Fatalf("pipeline=1: %v", err)
	}
	t.Logf("LOCALIZE h2 pipeline=1 prod-shape: %.1f Mbit/s", mbps)
	const pipeline1MinMbps = 50.0
	if mbps < pipeline1MinMbps {
		t.Fatalf("h2 pipeline=1 prod-shape %.1f Mbit/s < %.0f — interactive echo/TUN path OPEN", mbps, pipeline1MinMbps)
	}
}

// bidi stream: unlimited background C2S often matches or beats deep pipeline, not prod TUN shape.
func TestLocalizeConnectUDPH2EchoPipeline256VsUnlimited(t *testing.T) {
	dur := connectUDPSynthProdBenchDuration
	echo := runUDPEcho(t, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	echoAddr := echo.LocalAddr().(*net.UDPAddr)
	proxyPort := startInProcessH2UDPConnectProxy(t)
	session, waitCtx := newConnectUDPProdProfileH2SessionWithLink(t, proxyPort, instantH2Link{})
	pkt, err := session.ListenPacket(waitCtx, M.Socksaddr{
		Addr: netip.MustParseAddr(echoAddr.IP.String()),
		Port: uint16(echoAddr.Port),
	})
	if err != nil {
		t.Fatalf("ListenPacket: %v", err)
	}
	defer func() { _ = pkt.Close() }()
	payloadLen := connectudp.DefaultBenchUDPPayloadLen
	_, pipeline256, err := benchConnectUDPPacketDownloadPipelined(t, pkt, echoAddr, dur, payloadLen, 256)
	if err != nil {
		t.Fatalf("pipeline256: %v", err)
	}
	_, unlimited, err := benchConnectUDPPacketDownloadPipelined(t, pkt, echoAddr, dur, payloadLen, 0)
	if err != nil {
		t.Fatalf("unlimited: %v", err)
	}
	ratio := unlimited / pipeline256
	t.Logf("LOCALIZE h2 echo pipeline256=%.1f unlimited=%.1f ratio=%.2f", pipeline256, unlimited, ratio)
	const pipelineMinMbps = 80.0
	if pipeline256 >= pipelineMinMbps && unlimited < 0.85*pipeline256 {
		t.Fatalf("unlimited echo %.1f < 85%% of pipeline256 %.1f — unbounded C2S regressed vs bounded in-flight", unlimited, pipeline256)
	}
}

// TestLocalizeConnectUDPH2DownloadFountain logs S2C-only receive (server UDP flood after prime).
func TestLocalizeConnectUDPH2DownloadFountain(t *testing.T) {
	dur := connectUDPSynthProdBenchDuration
	fountain := startUDPFountain(t, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	fountainAddr := fountain.LocalAddr().(*net.UDPAddr)
	proxyPort := startInProcessH2UDPConnectProxy(t)
	session, waitCtx := newConnectUDPProdProfileH2SessionWithLink(t, proxyPort, instantH2Link{})
	pkt, err := session.ListenPacket(waitCtx, M.Socksaddr{
		Addr: netip.MustParseAddr(fountainAddr.IP.String()),
		Port: uint16(fountainAddr.Port),
	})
	if err != nil {
		t.Fatalf("ListenPacket: %v", err)
	}
	defer func() { _ = pkt.Close() }()
	primeUDPBench(t, pkt, fountainAddr)
	_, mbps, err := benchConnectUDPPacketReceiveOnly(t, pkt, dur, connectudp.DefaultBenchUDPPayloadLen)
	if err != nil {
		t.Fatalf("fountain receive: %v", err)
	}
	t.Logf("LOCALIZE connect-udp-h2 download fountain-flood (S2C-only): %.1f Mbit/s", mbps)
	if mbps < connectUDPSynthInstantMinMbps {
		t.Fatalf("%s", synthKPIDiagnostic("L4 connect-udp-h2 prod", "udp_down_fountain", mbps, connectUDPSynthInstantMinMbps,
			"S2C-only fountain — inline downlink scan / server relay ceiling"))
	}
}

// TestLocalizeConnectUDPH2DownloadFountainMaxCapsule logs S2C fountain at max RFC9297 capsule payload.
func TestLocalizeConnectUDPH2DownloadFountainMaxCapsule(t *testing.T) {
	dur := connectUDPSynthProdBenchDuration
	maxPayload := h2c.MaxUDPPayloadPerDatagramCapsule()
	fountain := startUDPFountain(t, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	fountainAddr := fountain.LocalAddr().(*net.UDPAddr)
	proxyPort := startInProcessH2UDPConnectProxy(t)
	session, waitCtx := newConnectUDPProdProfileH2SessionWithLink(t, proxyPort, instantH2Link{})
	pkt, err := session.ListenPacket(waitCtx, M.Socksaddr{
		Addr: netip.MustParseAddr(fountainAddr.IP.String()),
		Port: uint16(fountainAddr.Port),
	})
	if err != nil {
		t.Fatalf("ListenPacket: %v", err)
	}
	defer func() { _ = pkt.Close() }()
	primeUDPBench(t, pkt, fountainAddr)
	_, mbps, err := benchConnectUDPPacketReceiveOnly(t, pkt, dur, maxPayload)
	if err != nil {
		t.Fatalf("fountain receive max capsule: %v", err)
	}
	t.Logf("LOCALIZE connect-udp-h2 fountain maxCapsule(%dB): %.1f Mbit/s", maxPayload, mbps)
}

// TestLocalizeConnectUDPH2EchoDuplexGapWithFountain compares echo-duplex vs fountain S2C on H2.
// Each leg uses a fresh session — reusing one session after Close() yields echo=0 (false gap).
func TestLocalizeConnectUDPH2EchoDuplexGapWithFountain(t *testing.T) {
	dur := connectUDPSynthProdBenchDuration
	fountain := startUDPFountain(t, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	fountainAddr := fountain.LocalAddr().(*net.UDPAddr)
	echo := runUDPEcho(t, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	echoAddr := echo.LocalAddr().(*net.UDPAddr)

	fountainProxy := startInProcessH2UDPConnectProxy(t)
	fountainSession, fountainCtx := newConnectUDPProdProfileH2SessionWithLink(t, fountainProxy, instantH2Link{})
	fountainPkt, err := fountainSession.ListenPacket(fountainCtx, M.Socksaddr{
		Addr: netip.MustParseAddr(fountainAddr.IP.String()),
		Port: uint16(fountainAddr.Port),
	})
	if err != nil {
		t.Fatalf("ListenPacket fountain: %v", err)
	}
	primeUDPBench(t, fountainPkt, fountainAddr)
	_, fountainMbps, err := benchConnectUDPPacketReceiveOnly(t, fountainPkt, dur, connectudp.DefaultBenchUDPPayloadLen)
	_ = fountainPkt.Close()
	if err != nil {
		t.Fatalf("fountain receive: %v", err)
	}

	echoProxy := startInProcessH2UDPConnectProxy(t)
	echoSession, echoCtx := newConnectUDPProdProfileH2SessionWithLink(t, echoProxy, instantH2Link{})
	echoPkt, err := echoSession.ListenPacket(echoCtx, M.Socksaddr{
		Addr: netip.MustParseAddr(echoAddr.IP.String()),
		Port: uint16(echoAddr.Port),
	})
	if err != nil {
		t.Fatalf("ListenPacket echo: %v", err)
	}
	defer func() { _ = echoPkt.Close() }()
	_, echoMbps, err := benchConnectUDPPacketDownloadViaEcho(t, echoPkt, echoAddr, dur, connectudp.DefaultBenchUDPPayloadLen)
	if err != nil {
		t.Fatalf("echo-duplex: %v", err)
	}
	ratio := echoMbps / fountainMbps
	t.Logf("LOCALIZE h2 echo-duplex gap: fountain=%.1f echo=%.1f ratio=%.2f (want ratio>=0.75 when fountain>=400)",
		fountainMbps, echoMbps, ratio)
	if fountainMbps >= 400 && ratio < 0.75 {
		t.Fatalf("h2 echo-duplex %.1f Mbit/s < 75%% of fountain %.1f — H2 bidi capsule contention", echoMbps, fountainMbps)
	}
}

// TestLocalizeConnectUDPH2DownloadFountainPayloadScaling checks whether H2 S2C fountain is
// per-datagram decode bound (weak ratio) vs wire bandwidth bound.
func TestLocalizeConnectUDPH2DownloadFountainPayloadScaling(t *testing.T) {
	dur := connectUDPSynthProdBenchDuration
	runFountain := func(payloadLen int) float64 {
		fountain := startUDPFountain(t, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
		fountainAddr := fountain.LocalAddr().(*net.UDPAddr)
		proxyPort := startInProcessH2UDPConnectProxy(t)
		session, waitCtx := newConnectUDPProdProfileH2SessionWithLink(t, proxyPort, instantH2Link{})
		pkt, err := session.ListenPacket(waitCtx, M.Socksaddr{
			Addr: netip.MustParseAddr(fountainAddr.IP.String()),
			Port: uint16(fountainAddr.Port),
		})
		if err != nil {
			t.Fatalf("ListenPacket: %v", err)
		}
		defer func() { _ = pkt.Close() }()
		primeUDPBench(t, pkt, fountainAddr)
		_, mbps, err := benchConnectUDPPacketReceiveOnly(t, pkt, dur, payloadLen)
		if err != nil {
			t.Fatalf("fountain receive payloadLen=%d: %v", payloadLen, err)
		}
		return mbps
	}
	mbps512 := runFountain(connectudp.DefaultBenchUDPPayloadLen)
	maxPayload := h2c.MaxUDPPayloadPerDatagramCapsule()
	mbpsMax := runFountain(maxPayload)
	ratio := mbpsMax / mbps512
	t.Logf("LOCALIZE h2 fountain payload scaling: 512B=%.1f maxCapsule(%dB)=%.1f ratio=%.2f",
		mbps512, maxPayload, mbpsMax, ratio)
	// PPS/decode ceiling: maxCapsule materially faster than 512B while 512B stays low.
	if mbps512 >= 200 && mbps512 < connectUDPSynthInstantMinMbps && ratio >= 1.25 {
		t.Fatalf("h2 S2C fountain PPS/decode asymmetry (512=%.1f max=%.1f ratio=%.2f)",
			mbps512, mbpsMax, ratio)
	}
}

// TestLocalizeConnectUDPH2UploadPayloadScaling checks whether H2 upload is PPS/capsule-bound.
func TestLocalizeConnectUDPH2UploadPayloadScaling(t *testing.T) {
	dur := connectUDPSynthProdBenchDuration
	_, mbps512, err := benchConnectUDPProdProfileH2Upload(t, instantH2Link{}, dur, 0, 512)
	if err != nil {
		t.Fatalf("h2 upload 512B: %v", err)
	}
	maxPayload := h2c.MaxUDPPayloadPerDatagramCapsule()
	_, mbpsMax, err := benchConnectUDPProdProfileH2Upload(t, instantH2Link{}, dur, 0, maxPayload)
	if err != nil {
		t.Fatalf("h2 upload max capsule: %v", err)
	}
	ratio := mbpsMax / mbps512
	t.Logf("LOCALIZE h2 upload payload scaling: 512B=%.1f maxCapsule(%dB)=%.1f ratio=%.2f",
		mbps512, maxPayload, mbpsMax, ratio)
	if mbps512 >= 300 && ratio < 1.15 {
		t.Fatalf("h2 upload weak payload scaling (512=%.1f max=%.1f ratio=%.2f) — per-capsule/PPS ceiling",
			mbps512, mbpsMax, ratio)
	}
}

// TestLocalizeConnectUDPH2UploadVsConnectStreamAnchor compares H2 CONNECT-UDP upload with
// connect-stream upload on the same in-proc H2 proxy + SOCKS path. FAIL when stream is fast
// but UDP upload is structurally capped (wire ceiling), not when both legs are slow.
func TestLocalizeConnectUDPH2UploadVsConnectStreamAnchor(t *testing.T) {
	dur := connectUDPSynthProdBenchDuration
	_, udpMbps, err := benchConnectUDPProdProfileH2Upload(t, instantH2Link{}, dur, 0, connectudp.DefaultBenchUDPPayloadLen)
	if err != nil {
		t.Fatalf("h2 connect-udp upload: %v", err)
	}
	proxyPort := startInProcessH2TCPConnectStreamProxy(t)
	socksPort := startH2ConnectStreamSocksRouter(t, proxyPort)
	targetPort := startH2ConnectStreamUploadTarget(t)
	conn := socksTCPDial(t, socksPort, targetPort)
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(dur + 5*time.Second)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}
	_, streamMbps, err := measureTCPUploadMbps(conn, dur)
	if err != nil {
		t.Fatalf("h2 connect-stream upload: %v", err)
	}
	ratio := udpMbps / streamMbps
	t.Logf("LOCALIZE h2 upload vs connect-stream: udp=%.1f stream=%.1f ratio=%.2f (want ratio>=0.75 when stream>=800)",
		udpMbps, streamMbps, ratio)
	if streamMbps >= 800 && ratio < 0.75 {
		t.Fatalf("connect-udp h2 upload %.1f Mbit/s < 75%% of connect-stream %.1f — separate H2 wire path ceiling",
			udpMbps, streamMbps)
	}
}

func measureTCPUploadMbpsWriteSize(conn net.Conn, duration time.Duration, writeSize int) (int64, float64, error) {
	if writeSize <= 0 {
		writeSize = 1
	}
	deadline := time.Now().Add(duration)
	buf := make([]byte, writeSize)
	var total int64
	for time.Now().Before(deadline) {
		_ = conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
		n, err := conn.Write(buf)
		if n > 0 {
			total += int64(n)
		}
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() && total > 0 {
				break
			}
			if err == io.EOF {
				break
			}
			if total > 0 {
				break
			}
			return 0, 0, err
		}
	}
	secs := duration.Seconds()
	if secs <= 0 {
		secs = 1
	}
	return total, float64(total*8) / secs / 1e6, nil
}

// TestLocalizeConnectUDPH2UploadVsConnectStreamSameWriteSize compares CONNECT-UDP with connect-stream
// when both use DefaultBenchUDPPayloadLen (512 B) writes — separates bench write-size skew from capsule wire path.
func TestLocalizeConnectUDPH2UploadVsConnectStreamSameWriteSize(t *testing.T) {
	dur := connectUDPSynthProdBenchDuration
	payloadLen := connectudp.DefaultBenchUDPPayloadLen
	_, udpMbps, err := benchConnectUDPProdProfileH2Upload(t, instantH2Link{}, dur, 0, payloadLen)
	if err != nil {
		t.Fatalf("h2 connect-udp upload: %v", err)
	}
	proxyPort := startInProcessH2TCPConnectStreamProxy(t)
	socksPort := startH2ConnectStreamSocksRouter(t, proxyPort)
	targetPort := startH2ConnectStreamUploadTarget(t)
	conn := socksTCPDial(t, socksPort, targetPort)
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(dur + 5*time.Second)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}
	_, streamMbps, err := measureTCPUploadMbpsWriteSize(conn, dur, payloadLen)
	if err != nil {
		t.Fatalf("h2 connect-stream upload (%d B writes): %v", payloadLen, err)
	}
	ratio := udpMbps / streamMbps
	t.Logf("LOCALIZE h2 fair write %dB: udp=%.1f stream=%.1f ratio=%.2f (want ratio>=0.75 when stream>=400)",
		payloadLen, udpMbps, streamMbps, ratio)
	if streamMbps >= 400 && ratio < 0.75 {
		t.Fatalf("connect-udp h2 upload %.1f Mbit/s < 75%% of connect-stream %.1f at same %d B write — RFC9297 capsule path ceiling",
			udpMbps, streamMbps, payloadLen)
	}
}

// TestLocalizeConnectUDPH2UploadDirectDialVsListenPacket compares DialH2Overlay (wire path only)
// with prod ListenPacket (+ DatagramSplitConn). FAIL when session wrapper is the bottleneck.
func TestLocalizeConnectUDPH2UploadDirectDialVsListenPacket(t *testing.T) {
	dur := connectUDPSynthProdBenchDuration
	_, directMbps, err := benchConnectUDPH2OverlayDirectUpload(t, instantH2Link{}, dur, connectudp.DefaultBenchUDPPayloadLen)
	if err != nil {
		t.Fatalf("h2 overlay direct upload: %v", err)
	}
	_, listenMbps, err := benchConnectUDPProdProfileH2Upload(t, instantH2Link{}, dur, 0, connectudp.DefaultBenchUDPPayloadLen)
	if err != nil {
		t.Fatalf("h2 ListenPacket upload: %v", err)
	}
	ratio := directMbps / listenMbps
	t.Logf("LOCALIZE h2 direct overlay vs ListenPacket upload: direct=%.1f listen=%.1f ratio=%.2f (want 0.85–1.15 when listen>=300)",
		directMbps, listenMbps, ratio)
	if listenMbps >= 300 && (ratio < 0.85 || ratio > 1.15) {
		t.Fatalf("ListenPacket vs DialH2Overlay upload gap (direct=%.1f listen=%.1f ratio=%.2f) — session/wrapper overhead or divergent wire path",
			directMbps, listenMbps, ratio)
	}
}

// TestLocalizeConnectUDPH2DownloadFountainDirectDialVsListenPacket compares DialH2Overlay fountain
// S2C with prod ListenPacket. FAIL when DatagramSplitConn/session is the download bottleneck.
// ListenPacket runs first so a prior direct-dial flood does not starve the wrapper path.
func TestLocalizeConnectUDPH2DownloadFountainDirectDialVsListenPacket(t *testing.T) {
	dur := connectUDPSynthProdBenchDuration
	fountain := startUDPFountain(t, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	fountainAddr := fountain.LocalAddr().(*net.UDPAddr)
	proxyPort := startInProcessH2UDPConnectProxy(t)
	session, waitCtx := newConnectUDPProdProfileH2SessionWithLink(t, proxyPort, instantH2Link{})
	pkt, err := session.ListenPacket(waitCtx, M.Socksaddr{
		Addr: netip.MustParseAddr(fountainAddr.IP.String()),
		Port: uint16(fountainAddr.Port),
	})
	if err != nil {
		t.Fatalf("ListenPacket: %v", err)
	}
	primeUDPBench(t, pkt, fountainAddr)
	_, listenMbps, err := benchConnectUDPPacketReceiveOnly(t, pkt, dur, connectudp.DefaultBenchUDPPayloadLen)
	_ = pkt.Close()
	_ = session.Close()
	if err != nil {
		t.Fatalf("ListenPacket fountain receive: %v", err)
	}

	_, directMbps, err := benchConnectUDPH2OverlayDirectDownloadFountain(t, instantH2Link{}, dur, connectudp.DefaultBenchUDPPayloadLen)
	if err != nil {
		t.Fatalf("h2 overlay direct fountain download: %v", err)
	}
	ratio := directMbps / listenMbps
	t.Logf("LOCALIZE h2 direct overlay vs ListenPacket fountain download: direct=%.1f listen=%.1f ratio=%.2f (want 0.85–1.15 when listen>=300)",
		directMbps, listenMbps, ratio)
	if listenMbps >= 300 && (ratio < 0.85 || ratio > 1.15) {
		t.Fatalf("ListenPacket vs DialH2Overlay fountain gap (direct=%.1f listen=%.1f ratio=%.2f) — session/wrapper overhead or divergent wire path",
			directMbps, listenMbps, ratio)
	}
}
