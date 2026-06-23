package masque

// H3 CONNECT-UDP client harness: direct DialH3Production vs CoreSession ListenPacket (parity with connectudp_h2_harness_test.go).

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"testing"
	"time"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/transport/masque/connectudp"
	cudpclient "github.com/sagernet/sing-box/transport/masque/connectudp/client"
	cudpsplit "github.com/sagernet/sing-box/transport/masque/connectudp/split"
	h3t "github.com/sagernet/sing-box/transport/masque/h3"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/yosida95/uritemplate/v3"
)

func dialH3ConnectUDPDirect(tb testing.TB, proxyPort int, target string) net.PacketConn {
	tb.Helper()
	clientTLS := connectUDPTestTLS.Clone()
	clientTLS.InsecureSkipVerify = true
	clientTLS.ServerName = "127.0.0.1"
	client := cudpclient.NewQUICClient(cudpclient.QUICClientConfig{
		TLSClientConfig: clientTLS,
		QUICConfig:      h3t.NewPacketPlaneQUICConfig(),
	})
	rawTpl := fmt.Sprintf("https://127.0.0.1:%d/masque/udp/{target_host}/{target_port}", proxyPort)
	tpl, err := uritemplate.New(rawTpl)
	if err != nil {
		tb.Fatalf("template: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	tb.Cleanup(cancel)
	raw, err := cudpclient.DialH3Production(ctx, nil, client, tpl, target)
	if err != nil {
		tb.Fatalf("DialH3Production: %v", err)
	}
	tb.Cleanup(func() { _ = raw.Close() })
	return cudpsplit.NewDatagramSplitConn(raw, cudpsplit.DatagramSplitOptions{
		MaxPayload: connectudp.DefaultBenchUDPPayloadLen,
		HTTPLayer:  option.MasqueHTTPLayerH3,
	})
}

func benchConnectUDPH3DirectDownloadFountainWithProxy(
	tb testing.TB,
	register func(testing.TB, *http.ServeMux, int),
	duration time.Duration,
	payloadLen int,
) (int64, float64, error) {
	tb.Helper()
	if payloadLen <= 0 {
		payloadLen = connectudp.DefaultBenchUDPPayloadLen
	}
	fountain := startUDPFountain(tb, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	fountainAddr := fountain.LocalAddr().(*net.UDPAddr)
	proxyPort := startInProcessMasqueUDPProxy(tb, func(mux *http.ServeMux, proxyPort int) {
		register(tb, mux, proxyPort)
	})
	target := net.JoinHostPort(fountainAddr.IP.String(), strconv.Itoa(fountainAddr.Port))
	pkt := dialH3ConnectUDPDirect(tb, proxyPort, target)
	if err := primeUDPBenchErr(tb, pkt, fountainAddr); err != nil {
		return 0, 0, err
	}
	return benchConnectUDPPacketReceiveOnly(tb, pkt, duration, payloadLen)
}

func benchConnectUDPH3DirectDownloadFountain(
	tb testing.TB,
	duration time.Duration,
	payloadLen int,
) (int64, float64, error) {
	return benchConnectUDPH3DirectDownloadFountainWithProxy(tb, registerMasqueUDPProxyHandler, duration, payloadLen)
}

// TestLocalizeConnectUDPH3FountainRelayVsRef compares our relay S2C path vs masque-go ref proxy.
func TestLocalizeConnectUDPH3FountainRelayVsRef(t *testing.T) {
	dur := connectUDPSynthProdBenchDuration
	_, ours, err := benchConnectUDPH3DirectDownloadFountainWithProxy(t, registerMasqueUDPProxyHandler, dur, connectudp.DefaultBenchUDPPayloadLen)
	if err != nil {
		t.Fatalf("ours fountain: %v", err)
	}
	_, ref, err := benchConnectUDPH3DirectDownloadFountainWithProxy(t, registerMasqueGoRefUDPProxyHandler, dur, connectudp.DefaultBenchUDPPayloadLen)
	if err != nil {
		t.Fatalf("ref fountain: %v", err)
	}
	t.Logf("LOCALIZE h3 fountain relay ours=%.1f ref=%.1f ratio=%.2f", ours, ref, ours/ref)
}

// TestBenchConnectUDPH3FountainDirect is B2: full QUIC/datagram stack without CoreSession (~2s).
func TestBenchConnectUDPH3FountainDirect(t *testing.T) {
	dur := connectUDPSynthProdBenchDuration
	_, mbps, err := benchConnectUDPH3DirectDownloadFountain(t, dur, connectudp.DefaultBenchUDPPayloadLen)
	if err != nil {
		t.Fatalf("direct fountain: %v", err)
	}
	t.Logf("BENCH h3 fountain direct (QUIC stack, no CoreSession): %.1f Mbit/s", mbps)
}

// TestLocalizeConnectUDPH3DownloadFountainDirectDial compares direct DialH3Production vs CoreSession ListenPacket.
func TestLocalizeConnectUDPH3DownloadFountainDirectDial(t *testing.T) {
	dur := connectUDPSynthProdBenchDuration
	_, directMbps, err := benchConnectUDPH3DirectDownloadFountain(t, dur, connectudp.DefaultBenchUDPPayloadLen)
	if err != nil {
		t.Fatalf("direct fountain: %v", err)
	}
	t.Logf("LOCALIZE h3 fountain direct DialH3Production: %.1f Mbit/s", directMbps)

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
	_, sessionMbps, err := benchConnectUDPPacketReceiveOnly(t, pkt, dur, connectudp.DefaultBenchUDPPayloadLen)
	if err != nil {
		t.Fatalf("session fountain: %v", err)
	}
	t.Logf("LOCALIZE h3 fountain CoreSession ListenPacket: %.1f Mbit/s", sessionMbps)
	ratio := directMbps / sessionMbps
	t.Logf("LOCALIZE h3 fountain direct/session ratio: %.2f", ratio)
}

// TestLocalizeConnectUDPH3EchoDirectDialVsListenPacket compares echo-duplex via DialH3Production
// vs CoreSession ListenPacket (+ DatagramSplitConn). Session runs first (warmup parity with fountain localize).
func TestLocalizeConnectUDPH3EchoDirectDialVsListenPacket(t *testing.T) {
	dur := connectUDPSynthProdBenchDuration
	echo := runUDPEcho(t, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	echoAddr := echo.LocalAddr().(*net.UDPAddr)
	target := net.JoinHostPort(echoAddr.IP.String(), strconv.Itoa(echoAddr.Port))
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
	sessionPkt, err := session.ListenPacket(waitCtx, M.Socksaddr{
		Addr: netip.MustParseAddr(echoAddr.IP.String()),
		Port: uint16(echoAddr.Port),
	})
	if err != nil {
		t.Fatalf("ListenPacket: %v", err)
	}
	defer func() { _ = sessionPkt.Close() }()
	_, sessionMbps, err := benchConnectUDPPacketDownloadViaEcho(t, sessionPkt, echoAddr, dur, connectudp.DefaultBenchUDPPayloadLen)
	if err != nil {
		t.Fatalf("session echo: %v", err)
	}

	directPkt := dialH3ConnectUDPDirect(t, proxyPort, target)
	_, directMbps, err := benchConnectUDPPacketDownloadViaEcho(t, directPkt, echoAddr, dur, connectudp.DefaultBenchUDPPayloadLen)
	if err != nil {
		t.Fatalf("direct echo: %v", err)
	}

	ratio := directMbps / sessionMbps
	t.Logf("LOCALIZE h3 echo session ListenPacket=%.1f direct DialH3Production=%.1f ratio=%.2f",
		sessionMbps, directMbps, ratio)
	if sessionMbps >= 300 && (ratio < 0.85 || ratio > 1.15) {
		t.Fatalf("echo direct vs session gap (session=%.1f direct=%.1f ratio=%.2f)", sessionMbps, directMbps, ratio)
	}
}
