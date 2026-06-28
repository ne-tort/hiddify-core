package masque

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"testing"
	"time"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/transport/masque/connectudp"
	M "github.com/sagernet/sing/common/metadata"
)

func InttestBenchConnectUDPH3FountainDirect(t *testing.T) {
	dur := connectUDPSynthProdBenchDuration
	_, mbps, err := benchConnectUDPH3DirectDownloadFountain(t, dur, connectudp.DefaultBenchUDPPayloadLen)
	if err != nil {
		t.Fatalf("direct fountain: %v", err)
	}
	t.Logf("BENCH h3 fountain direct (QUIC stack, no CoreSession): %.1f Mbit/s", mbps)
}

func InttestLocalizeConnectUDPH3DownloadFountainDirectDial(t *testing.T) {
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

func InttestLocalizeConnectUDPH3EchoDirectDialVsListenPacket(t *testing.T) {
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
