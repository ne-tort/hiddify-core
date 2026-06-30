package masque

// H2 CONNECT-UDP session dial helpers (inttest localize — UDP-STRUCT-12).

import (
	"context"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/sagernet/sing-box/transport/masque/connectudp"
)

// dialConnectUDPH2ViaSession dials CONNECT-UDP over H2 via prod dialUDPOverHTTP2 (same as client.DialAddr H2 leg).
func dialConnectUDPH2ViaSession(tb testing.TB, session ClientSession, ctx context.Context, target string) net.PacketConn {
	tb.Helper()
	cs, ok := session.(*coreSession)
	if !ok || cs == nil {
		tb.Fatalf("dialConnectUDPH2ViaSession: need *coreSession, got %T", session)
	}
	cs.Mu.Lock()
	tpl := cs.TemplateUDP
	cs.Mu.Unlock()
	pc, err := cs.dialUDPOverHTTP2(ctx, tpl, target)
	if err != nil {
		tb.Fatalf("dialUDPOverHTTP2: %v", err)
	}
	tb.Cleanup(func() { _ = pc.Close() })
	return pc
}

func benchConnectUDPH2SessionDirectUpload(
	tb testing.TB,
	link h2TransportLink,
	duration time.Duration,
	payloadLen int,
) (int64, float64, error) {
	tb.Helper()
	if payloadLen <= 0 {
		payloadLen = connectudp.DefaultBenchUDPPayloadLen
	}
	sink, sinkRx := runUDPSink(tb, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	sinkAddr := sink.LocalAddr().(*net.UDPAddr)
	proxyPort := startInProcessH2UDPConnectProxy(tb)
	session, waitCtx := newConnectUDPProdProfileH2SessionWithLinkTB(tb, proxyPort, link)
	target := net.JoinHostPort(sinkAddr.IP.String(), strconv.Itoa(sinkAddr.Port))
	pkt := dialConnectUDPH2ViaSession(tb, session, waitCtx, target)
	return benchConnectUDPPacketUpload(tb, pkt, sinkAddr, duration, 0, payloadLen, sinkRx)
}

func benchConnectUDPH2SessionDirectDownloadFountain(
	tb testing.TB,
	link h2TransportLink,
	duration time.Duration,
	payloadLen int,
) (int64, float64, error) {
	tb.Helper()
	if payloadLen <= 0 {
		payloadLen = connectudp.DefaultBenchUDPPayloadLen
	}
	fountain := startUDPFountain(tb, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	fountainAddr := fountain.LocalAddr().(*net.UDPAddr)
	proxyPort := startInProcessH2UDPConnectProxy(tb)
	session, waitCtx := newConnectUDPProdProfileH2SessionWithLinkTB(tb, proxyPort, link)
	target := net.JoinHostPort(fountainAddr.IP.String(), strconv.Itoa(fountainAddr.Port))
	pkt := dialConnectUDPH2ViaSession(tb, session, waitCtx, target)
	if err := primeUDPBenchErr(tb, pkt, fountainAddr); err != nil {
		return 0, 0, err
	}
	return benchConnectUDPPacketReceiveOnly(tb, pkt, duration, payloadLen)
}

// benchConnectUDPH2OverlayDirectUpload is an alias for the prod session dial path (STRUCT-12).
func benchConnectUDPH2OverlayDirectUpload(
	tb testing.TB,
	link h2TransportLink,
	duration time.Duration,
	payloadLen int,
) (int64, float64, error) {
	return benchConnectUDPH2SessionDirectUpload(tb, link, duration, payloadLen)
}

// benchConnectUDPH2OverlayDirectDownloadFountain is an alias for the prod session dial path (STRUCT-12).
func benchConnectUDPH2OverlayDirectDownloadFountain(
	tb testing.TB,
	link h2TransportLink,
	duration time.Duration,
	payloadLen int,
) (int64, float64, error) {
	return benchConnectUDPH2SessionDirectDownloadFountain(tb, link, duration, payloadLen)
}

// benchConnectUDPH2OverlayProdShapedUpload dials via prod session (EnsureTransport + NewTransport).
func benchConnectUDPH2OverlayProdShapedUpload(
	tb testing.TB,
	link h2TransportLink,
	duration time.Duration,
	payloadLen int,
) (int64, float64, error) {
	return benchConnectUDPH2SessionDirectUpload(tb, link, duration, payloadLen)
}
