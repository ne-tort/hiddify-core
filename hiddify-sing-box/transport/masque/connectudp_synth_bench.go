package masque

// Shared CONNECT-UDP synth bench helpers (regular build; inttest export + GATE tests).

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"runtime"
	"sync/atomic"
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

// benchConnectUDPProdProfileH3DownloadFountain measures S2C receive after prime (no concurrent C2S flood).
func benchConnectUDPProdProfileH3DownloadFountain(
	tb testing.TB,
	_ instantDatagramLink,
	duration time.Duration,
	payloadLen int,
) (int64, float64, error) {
	tb.Helper()
	if payloadLen <= 0 {
		payloadLen = connectudp.DefaultBenchUDPPayloadLen
	}
	fountain := startUDPFountain(tb, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	fountainAddr := fountain.LocalAddr().(*net.UDPAddr)
	pkt, _ := newConnectUDPH3ProdListenPacket(tb, M.Socksaddr{
		Addr: netip.MustParseAddr(fountainAddr.IP.String()),
		Port: uint16(fountainAddr.Port),
	})
	primeUDPBench(tb, pkt, fountainAddr)
	return benchConnectUDPPacketReceiveOnly(tb, pkt, duration, payloadLen)
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
		var err error
		if targetMbit <= 0 {
			err = writeToBenchUpload(pkt, payload, sinkAddr)
		} else {
			err = writeToWithStallGuard(tb, pkt, payload, sinkAddr, connectUDPSynthUploadWriteStall)
		}
		if err != nil {
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
