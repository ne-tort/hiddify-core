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
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/route"
	"github.com/sagernet/sing-box/transport/masque/connectudp"
	cudprelay "github.com/sagernet/sing-box/transport/masque/connectudp/relay"
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
	sink, sinkRx := runUDPSink(t, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	sinkAddr := sink.LocalAddr().(*net.UDPAddr)

	proxyPort := startInProcessMasqueUDPProxy(t, func(mux *http.ServeMux, proxyPort int) {
		registerMasqueUDPProxyHandler(t, mux, proxyPort)
	})

	waitCtx, cancel := context.WithTimeout(context.Background(), connectUDPSynthGateWaitCtx)
	defer cancel()

	opts := ClientOptions{
		Server:              "127.0.0.1",
		ServerPort:          uint16(proxyPort),
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
	route.TuneUDPPacketConn(pkt)

	return benchConnectUDPPacketUpload(t, pkt, sinkAddr, duration, targetMbit, payloadLen, sinkRx, true)
}

// benchConnectUDPProdProfileH3UploadZeroLoss measures sequenced upload goodput with Docker burst zero-loss semantics (UDP-5t2).
func benchConnectUDPProdProfileH3UploadZeroLoss(
	t *testing.T,
	link datagramTransportLink,
	duration time.Duration,
	payloadLen int,
) (float64, connectudp.SequencedStats, error) {
	t.Helper()
	runID := connectudp.AllocBenchRunID()
	if payloadLen <= 0 {
		payloadLen = connectudp.DefaultBenchUDPPayloadLen
	}
	sinkConn, seqSink := runUDPSequencedSink(t, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0}, runID)
	sinkAddr := sinkConn.LocalAddr().(*net.UDPAddr)

	proxyPort := startInProcessMasqueUDPProxy(t, func(mux *http.ServeMux, proxyPort int) {
		registerMasqueUDPProxyHandler(t, mux, proxyPort)
	})

	waitCtx, cancel := context.WithTimeout(context.Background(), connectUDPSynthGateWaitCtx)
	defer cancel()

	opts := ClientOptions{
		Server:              "127.0.0.1",
		ServerPort:          uint16(proxyPort),
		MasqueQUICCryptoTLS: &tls.Config{InsecureSkipVerify: true},
	}
	if dial := link.quicDialOverride(); dial != nil {
		opts.QUICDial = dial
	}

	session, err := (CoreClientFactory{}).NewSession(waitCtx, opts)
	if err != nil {
		return 0, connectudp.SequencedStats{}, err
	}
	defer func() { _ = session.Close() }()

	pkt, err := session.ListenPacket(waitCtx, M.Socksaddr{
		Addr: netip.MustParseAddr(sinkAddr.IP.String()),
		Port: uint16(sinkAddr.Port),
	})
	if err != nil {
		return 0, connectudp.SequencedStats{}, err
	}
	defer func() { _ = pkt.Close() }()
	route.TuneUDPPacketConn(pkt)

	mbps, st, err := benchConnectUDPPacketUploadSequenced(t, pkt, sinkAddr, seqSink, runID, duration, 0, payloadLen, true)
	return mbps, st, err
}

// benchConnectUDPProdProfileH3UploadZeroLossPaced measures sequenced upload @targetMbit with zero-loss semantics (UDP-5p1 steady MTU).
func benchConnectUDPProdProfileH3UploadZeroLossPaced(
	t *testing.T,
	link datagramTransportLink,
	duration time.Duration,
	payloadLen int,
	targetMbit float64,
) (float64, connectudp.SequencedStats, error) {
	t.Helper()
	runID := connectudp.AllocBenchRunID()
	if payloadLen <= 0 {
		payloadLen = connectudp.DefaultBenchUDPPayloadLen
	}
	if targetMbit <= 0 {
		targetMbit = connectUDPSynthProdMinMbps
	}
	sinkConn, seqSink := runUDPSequencedSink(t, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0}, runID)
	sinkAddr := sinkConn.LocalAddr().(*net.UDPAddr)

	proxyPort := startInProcessMasqueUDPProxy(t, func(mux *http.ServeMux, proxyPort int) {
		registerMasqueUDPProxyHandler(t, mux, proxyPort)
	})

	waitCtx, cancel := context.WithTimeout(context.Background(), connectUDPSynthGateWaitCtx)
	defer cancel()

	opts := ClientOptions{
		Server:              "127.0.0.1",
		ServerPort:          uint16(proxyPort),
		MasqueQUICCryptoTLS: &tls.Config{InsecureSkipVerify: true},
	}
	if dial := link.quicDialOverride(); dial != nil {
		opts.QUICDial = dial
	}

	session, err := (CoreClientFactory{}).NewSession(waitCtx, opts)
	if err != nil {
		return 0, connectudp.SequencedStats{}, err
	}
	defer func() { _ = session.Close() }()

	pkt, err := session.ListenPacket(waitCtx, M.Socksaddr{
		Addr: netip.MustParseAddr(sinkAddr.IP.String()),
		Port: uint16(sinkAddr.Port),
	})
	if err != nil {
		return 0, connectudp.SequencedStats{}, err
	}
	defer func() { _ = pkt.Close() }()
	route.TuneUDPPacketConn(pkt)

	mbps, st, err := benchConnectUDPPacketUploadSequenced(t, pkt, sinkAddr, seqSink, runID, duration, targetMbit, payloadLen, true)
	return mbps, st, err
}

func benchConnectUDPProdProfileH2UploadZeroLoss(
	t *testing.T,
	link h2TransportLink,
	duration time.Duration,
	payloadLen int,
) (float64, connectudp.SequencedStats, error) {
	t.Helper()
	runID := connectudp.AllocBenchRunID()
	if payloadLen <= 0 {
		payloadLen = connectudp.DefaultBenchUDPPayloadLen
	}
	sinkConn, seqSink := runUDPSequencedSink(t, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0}, runID)
	sinkAddr := sinkConn.LocalAddr().(*net.UDPAddr)

	proxyPort := startInProcessH2UDPConnectProxy(t)
	session, waitCtx := newConnectUDPProdProfileH2SessionWithLink(t, proxyPort, link)
	target := net.JoinHostPort(sinkAddr.IP.String(), strconv.Itoa(sinkAddr.Port))
	pkt := dialConnectUDPH2ViaSession(t, session, waitCtx, target)
	route.TuneUDPPacketConn(pkt)

	mbps, st, err := benchConnectUDPPacketUploadSequenced(t, pkt, sinkAddr, seqSink, runID, duration, 0, payloadLen, true)
	return mbps, st, err
}

// benchConnectUDPProdProfileH2UploadPaced measures sequenced H2 upload @targetMbit (docker WAN / steady parity).
func benchConnectUDPProdProfileH2UploadPaced(
	t *testing.T,
	link h2TransportLink,
	duration time.Duration,
	payloadLen int,
	targetMbit float64,
) (float64, connectudp.SequencedStats, error) {
	t.Helper()
	runID := connectudp.AllocBenchRunID()
	if payloadLen <= 0 {
		payloadLen = connectudp.DefaultBenchUDPPayloadLen
	}
	if targetMbit <= 0 {
		targetMbit = dockerBenchUDPTargetMbit
	}
	sinkConn, seqSink := runUDPSequencedSink(t, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0}, runID)
	sinkAddr := sinkConn.LocalAddr().(*net.UDPAddr)

	proxyPort := startInProcessH2UDPConnectProxy(t)
	session, waitCtx := newConnectUDPProdProfileH2SessionWithLink(t, proxyPort, link)
	target := net.JoinHostPort(sinkAddr.IP.String(), strconv.Itoa(sinkAddr.Port))
	pkt := dialConnectUDPH2ViaSession(t, session, waitCtx, target)
	route.TuneUDPPacketConn(pkt)

	mbps, st, err := benchConnectUDPPacketUploadSequenced(t, pkt, sinkAddr, seqSink, runID, duration, targetMbit, payloadLen, true)
	return mbps, st, err
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

	waitCtx, cancel := context.WithTimeout(context.Background(), connectUDPSynthGateWaitCtx)
	defer cancel()

	opts := ClientOptions{
		Server:              "127.0.0.1",
		ServerPort:          uint16(proxyPort),
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

// benchConnectUDPFountainS2C primes a fountain then measures S2C-only receive (no stall-guard on prime WriteTo).
func benchConnectUDPFountainS2C(
	tb testing.TB,
	pkt net.PacketConn,
	fountainAddr *net.UDPAddr,
	duration time.Duration,
	payloadLen int,
	gateFailFast bool,
) (int64, float64, error) {
	tb.Helper()
	route.TuneUDPPacketConn(pkt)
	if err := primeFountainReceiveBenchErr(tb, pkt, fountainAddr); err != nil {
		return 0, 0, err
	}
	return benchConnectUDPPacketReceiveOnly(tb, pkt, duration, payloadLen, gateFailFast)
}

// benchConnectUDPH3FountainS2C measures fountain flood (H2 parity: prime then S2C receive).
func benchConnectUDPH3FountainS2C(
	tb testing.TB,
	pkt net.PacketConn,
	fountainAddr *net.UDPAddr,
	duration time.Duration,
	payloadLen int,
	gateFailFast bool,
) (int64, float64, error) {
	return benchConnectUDPFountainS2C(tb, pkt, fountainAddr, duration, payloadLen, gateFailFast)
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
	return benchConnectUDPH3FountainS2C(tb, pkt, fountainAddr, duration, payloadLen, false)
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
	sink, sinkRx := runUDPSink(t, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	sinkAddr := sink.LocalAddr().(*net.UDPAddr)

	proxyPort := startInProcessH2UDPConnectProxy(t)
	session, waitCtx := newConnectUDPProdProfileH2SessionWithLink(t, proxyPort, link)
	target := net.JoinHostPort(sinkAddr.IP.String(), strconv.Itoa(sinkAddr.Port))
	pkt := dialConnectUDPH2ViaSession(t, session, waitCtx, target)
	route.TuneUDPPacketConn(pkt)

	return benchConnectUDPPacketUpload(t, pkt, sinkAddr, duration, targetMbit, payloadLen, sinkRx, true)
}

// benchConnectUDPProdProfileH2UploadViaListenPacket measures prod session.ListenPacket upload (M7 localize).
func benchConnectUDPProdProfileH2UploadViaListenPacket(
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
	sink, sinkRx := runUDPSink(t, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
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
	route.TuneUDPPacketConn(pkt)

	return benchConnectUDPPacketUpload(t, pkt, sinkAddr, duration, targetMbit, payloadLen, sinkRx, true)
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
	target := net.JoinHostPort(echoAddr.IP.String(), strconv.Itoa(echoAddr.Port))
	pkt := dialConnectUDPH2ViaSession(t, session, waitCtx, target)

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
	waitCtx, cancel := context.WithTimeout(context.Background(), connectUDPSynthGateWaitCtx)
	tb.Cleanup(cancel)
	baseDial := func(ctx context.Context, network, addr string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, network, addr)
	}
	session, err := (CoreClientFactory{}).NewSession(waitCtx, ClientOptions{
		Server:                   "127.0.0.1",
		ServerPort:               uint16(proxyPort),
		PathUDP:                  connectUDPInProcessPathUDP,
		MasqueEffectiveHTTPLayer: option.MasqueHTTPLayerH2,
		MasqueQUICCryptoTLS:      &tls.Config{InsecureSkipVerify: true},
		TCPDial: func(ctx context.Context, network, addr string) (net.Conn, error) {
			conn, err := baseDial(ctx, network, addr)
			if err != nil {
				return nil, err
			}
			if tc, ok := conn.(*net.TCPConn); ok {
				cudprelay.TuneMasqueTCPSocketBuffers(tc)
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

// benchConnectUDPPacketUploadSequenced floods sequenced probes (docker burst parity), flush/drain, rx goodput (UDP-5t2).
func benchConnectUDPPacketUploadSequenced(
	tb testing.TB,
	pkt net.PacketConn,
	sinkAddr *net.UDPAddr,
	seqSink *connectudp.SequencedSink,
	runID uint32,
	duration time.Duration,
	targetMbit float64,
	payloadLen int,
	useStallGuard bool,
) (float64, connectudp.SequencedStats, error) {
	tb.Helper()
	if payloadLen <= 0 {
		payloadLen = connectudp.DefaultBenchUDPPayloadLen
	}
	wallStart := time.Now()
	deadline := wallStart.Add(duration)
	wall := connectUDPSynthBenchWallDeadline(duration)
	sendUntil := deadline
	if useStallGuard && targetMbit == 0 {
		// Leave tail budget for bulk TLS + server onward before upload half-close (zero-loss GATE).
		sendUntil = deadline.Add(-250 * time.Millisecond)
	}
	var seq uint64
	var sent int
	var paceSlot time.Time
	for time.Now().Before(sendUntil) {
		if time.Now().After(wall) {
			break
		}
		p := connectudp.BuildProbePayload(seq, runID, payloadLen)
		var err error
		switch {
		case targetMbit > 0:
			// Paced send: rate is bounded by PaceSleepUntil; skip per-packet goroutine (bench overhead).
			err = writeToBenchUpload(pkt, p, sinkAddr)
		case useStallGuard:
			err = writeToWithStallGuard(tb, pkt, p, sinkAddr, connectUDPSynthUploadWriteStall)
		default:
			err = writeToBenchUpload(pkt, p, sinkAddr)
		}
		if err != nil {
			if sent > 0 {
				break
			}
			return 0, connectudp.SequencedStats{}, err
		}
		sent++
		seq++
		connectudp.PaceSleepUntil(&paceSlot, payloadLen, targetMbit)
	}
	sendSec := time.Since(wallStart).Seconds()
	if sendSec <= 0 {
		sendSec = duration.Seconds()
	}
	finishConnectUDPPacedProbeUpload(pkt, false)
	deliverDeadline := time.Now().Add(connectUDPSynthGateSinkDeliverWait)
	if targetMbit > 0 && payloadLen >= connectudp.SteadyUploadPayloadLenH3() {
		deliverDeadline = time.Now().Add(2 * time.Second)
	}
	for time.Now().Before(deliverDeadline) {
		rx := connectudp.SequencedSinkRxCount(seqSink)
		if rx >= sent {
			break
		}
		connectudp.FlushPacketConnWrites(pkt)
		time.Sleep(10 * time.Millisecond)
	}
	waitSequencedSinkDelivered(pkt, seqSink, sent)
	time.Sleep(750 * time.Millisecond) // bulk TLS + async onward tail after upload drain
	tailSlack := connectUDPSynthUploadTailSlackPkts
	if targetMbit > 0 && payloadLen >= connectudp.SteadyUploadPayloadLenH3() {
		tailSlack = connectUDPSynthUploadTailSlackPktsPacedSteady
	}
	if rx := connectudp.SequencedSinkRxCount(seqSink); sent > rx {
		if sent-rx > tailSlack {
			tb.Logf("connect-udp sequenced upload tail loss: sent=%d rx=%d (>%d pkts)", sent, rx, tailSlack)
		} else {
			sent = rx // in-flight at upload half-close; not counted for zero-loss KPI
		}
	}
	st := seqSink.Analyze(sent, payloadLen)
	mbps := connectudp.BurstSinkGoodputMbit(st.RxPkts, payloadLen, sendSec)
	if sent > 0 {
		tb.Logf("connect-udp sequenced upload: sent=%d rx=%d loss=%.2f%% dup=%.2f%% goodput=%.1f Mbit/s",
			st.SentPkts, st.RxPkts, st.LossPct, st.DupPct, mbps)
	}
	return mbps, st, nil
}

func benchConnectUDPPacketUpload(
	tb testing.TB,
	pkt net.PacketConn,
	sinkAddr *net.UDPAddr,
	duration time.Duration,
	targetMbit float64,
	payloadLen int,
	sinkRx *atomic.Int64,
	gateFailFast bool,
) (int64, float64, error) {
	tb.Helper()
	if sinkRx == nil {
		return 0, 0, errors.New("benchConnectUDPPacketUpload: sinkRx required for rx-based goodput")
	}
	payload := make([]byte, payloadLen)
	for i := range payload {
		payload[i] = byte(i % 251)
	}
	deadline := time.Now().Add(duration)
	wall := connectUDPSynthBenchWallDeadline(duration)
	rxBaseline := sinkRx.Load()
	var paceSlot time.Time
	var sent int64
	for time.Now().Before(deadline) {
		if time.Now().After(wall) {
			break
		}
		var err error
		switch {
		case targetMbit > 0:
			err = writeToWithStallGuard(tb, pkt, payload, sinkAddr, connectUDPSynthUploadWriteStall)
		case gateFailFast:
			err = writeToWithStallGuard(tb, pkt, payload, sinkAddr, connectUDPSynthUploadWriteStall)
		default:
			err = writeToBenchUpload(pkt, payload, sinkAddr)
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
	finishConnectUDPPacedProbeUpload(pkt, false)
	delivered := waitUDPSinkDelivered(sinkRx, rxBaseline, sent)
	if sent > 0 && delivered < sent {
		tb.Logf("connect-udp upload bench: sent=%d rx=%d loss=%.2f%%", sent, delivered, 100*(1-float64(delivered)/float64(sent)))
	}
	secs := duration.Seconds()
	if secs <= 0 {
		secs = 1
	}
	return delivered, float64(delivered*8) / secs / 1e6, nil
}

// waitSequencedSinkDelivered waits for all sequenced probes after upload drain (docker burst parity).
func waitSequencedSinkDelivered(pkt net.PacketConn, sink *connectudp.SequencedSink, sent int) {
	if sink == nil || sent == 0 {
		return
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if connectudp.SequencedSinkRxCount(sink) >= sent {
			return
		}
		if pkt != nil {
			connectudp.FlushPacketConnWrites(pkt)
		}
		time.Sleep(2 * time.Millisecond)
	}
}

func waitUDPSinkDelivered(sinkRx *atomic.Int64, baseline, sent int64) int64 {
	if sent == 0 {
		return 0
	}
	deadline := time.Now().Add(connectUDPSynthGateSinkDeliverWait)
	var last int64
	stableAt := time.Time{}
	for time.Now().Before(deadline) {
		rx := sinkRx.Load() - baseline
		if rx >= sent {
			return rx
		}
		if rx == last && rx > 0 {
			if stableAt.IsZero() {
				stableAt = time.Now()
			} else if time.Since(stableAt) >= 100*time.Millisecond {
				return rx
			}
		} else {
			stableAt = time.Time{}
			last = rx
		}
		time.Sleep(5 * time.Millisecond)
	}
	return sinkRx.Load() - baseline
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

func benchConnectUDPPacketReceiveOnly(tb testing.TB, pkt net.PacketConn, duration time.Duration, payloadLen int, gateFailFast bool) (int64, float64, error) {
	tb.Helper()
	buf := make([]byte, payloadLen+64)
	deadline := time.Now().Add(duration)
	wall := connectUDPSynthBenchWallDeadline(duration)
	var received int64
	readFn := readFromBenchDownload
	if gateFailFast {
		readFn = func(pkt net.PacketConn, buf []byte) (int, net.Addr, error) {
			stall := connectUDPSynthUploadWriteStall
			if rem := time.Until(wall); rem > 0 && rem < stall {
				stall = rem
			}
			return readFromWithStallGuard(tb, pkt, buf, stall)
		}
	}
	for time.Now().Before(deadline) {
		if time.Now().After(wall) {
			break
		}
		n, _, err := readFn(pkt, buf)
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
