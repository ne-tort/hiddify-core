package masque

// Inttest localize gate runners (W-UDP-4 inttest MOVE). Bench helpers in connectudp_synth_bench.go.

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/netip"
	"os"
	"testing"
	"time"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/transport/masque/connectudp"
	M "github.com/sagernet/sing/common/metadata"
)

func inttestLocalizeEchoDuplexGateFail(t *testing.T, format string, args ...any) {
	t.Helper()
	if os.Getenv("HIDDIFY_LOCALIZE_ECHO_GATE") != "1" {
		t.Logf("OPEN (HIDDIFY_LOCALIZE_ECHO_GATE off): "+format, args...)
		return
	}
	t.Fatalf(format, args...)
}

// InttestLocalizeConnectUDPH3EchoBoundedPipeline64ProdShape is the primary H3 echo KPI (P0 3ck).
func InttestLocalizeConnectUDPH3EchoBoundedPipeline64ProdShape(t *testing.T) {
	t.Helper()
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
	depth := connectUDPEchoBoundedPipelineDepth
	_, mbps, err := benchConnectUDPPacketDownloadPipelined(t, pkt, echoAddr, dur, connectudp.DefaultBenchUDPPayloadLen, depth)
	if err != nil {
		t.Fatalf("pipeline=%d: %v", depth, err)
	}
	floor := connectUDPEchoBoundedPipelineMinMbps * (1 - connectUDPSynthInstantGateSlackPct)
	t.Logf("LOCALIZE h3 pipeline=%d prod-shape: %.1f Mbit/s (3ck floor %.0f)", depth, mbps, connectUDPEchoBoundedPipelineMinMbps)
	if mbps < floor {
		t.Fatalf("h3 pipeline=%d prod-shape %.1f Mbit/s < %.0f (3ck primary echo gate)", depth, mbps, connectUDPEchoBoundedPipelineMinMbps)
	}
}

// InttestLocalizeConnectUDPH3EchoDockerAbsoluteFloor mirrors docker/masque-perf-lab run_local.py SOCKS echo_floor.
func InttestLocalizeConnectUDPH3EchoDockerAbsoluteFloor(t *testing.T) {
	t.Helper()
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
	_, echoMbps, err := benchConnectUDPPacketDownloadViaEcho(t, pkt, echoAddr, dur, connectudp.DefaultBenchUDPPayloadLen)
	if err != nil {
		t.Fatalf("echo-duplex download: %v", err)
	}
	floor := connectUDPDockerEchoAbsoluteFloorMbps * (1 - connectUDPSynthInstantGateSlackPct)
	t.Logf("LOCALIZE h3 echo docker-parity: echo=%.1f floor=%.0f (run_local.py SOCKS)", echoMbps, connectUDPDockerEchoAbsoluteFloorMbps)
	if echoMbps < floor {
		t.Fatalf("h3 echo-duplex %.1f Mbit/s < docker parity floor %.0f", echoMbps, connectUDPDockerEchoAbsoluteFloorMbps)
	}
}

// InttestLocalizeConnectUDPH3EchoDuplexGap compares echo-duplex vs fountain S2C on H3.
func InttestLocalizeConnectUDPH3EchoDuplexGap(t *testing.T) {
	t.Helper()
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

	echoSession, echoCtx := openSession()
	echoPkt, err := echoSession.ListenPacket(echoCtx, M.Socksaddr{
		Addr: netip.MustParseAddr(echoAddr.IP.String()),
		Port: uint16(echoAddr.Port),
	})
	if err != nil {
		t.Fatalf("ListenPacket echo: %v", err)
	}
	_, echoMbps, err := benchConnectUDPPacketDownloadViaEcho(t, echoPkt, echoAddr, dur, connectudp.DefaultBenchUDPPayloadLen)
	_ = echoPkt.Close()
	if err != nil {
		t.Fatalf("echo-duplex download: %v", err)
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
	if err != nil {
		t.Fatalf("fountain receive: %v", err)
	}

	ratio := echoMbps / fountainMbps
	t.Logf("LOCALIZE echo-duplex gap: fountain=%.1f echo=%.1f ratio=%.2f (want ratio>=0.75 when fountain>=400)",
		fountainMbps, echoMbps, ratio)
	if fountainMbps >= 400 && ratio < 0.75 {
		inttestLocalizeEchoDuplexGateFail(t, "echo-duplex %.1f Mbit/s < 75%% of fountain %.1f — structural C2S/S2C contention on DATAGRAM plane", echoMbps, fountainMbps)
	}
}

// InttestLocalizeConnectUDPH2EchoDuplexGap compares H2 echo-duplex vs upload-only on the same host.
func InttestLocalizeConnectUDPH2EchoDuplexGap(t *testing.T) {
	t.Helper()
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
		inttestLocalizeEchoDuplexGateFail(t, "h2 echo-duplex %.1f Mbit/s < 75%% of upload-only %.1f — capsule duplex contention", echoMbps, uploadMbps)
	}
}

// InttestLocalizeConnectUDPH2EchoDuplexGapWithFountain compares echo-duplex vs fountain S2C on H2.
func InttestLocalizeConnectUDPH2EchoDuplexGapWithFountain(t *testing.T) {
	t.Helper()
	dur := connectUDPSynthProdBenchDuration
	fountain := startUDPFountain(t, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	fountainAddr := fountain.LocalAddr().(*net.UDPAddr)
	echo := runUDPEcho(t, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	echoAddr := echo.LocalAddr().(*net.UDPAddr)

	echoProxy := startInProcessH2UDPConnectProxy(t)
	echoSession, echoCtx := newConnectUDPProdProfileH2SessionWithLink(t, echoProxy, instantH2Link{})
	echoPkt, err := echoSession.ListenPacket(echoCtx, M.Socksaddr{
		Addr: netip.MustParseAddr(echoAddr.IP.String()),
		Port: uint16(echoAddr.Port),
	})
	if err != nil {
		t.Fatalf("ListenPacket echo: %v", err)
	}
	_, echoMbps, err := benchConnectUDPPacketDownloadViaEcho(t, echoPkt, echoAddr, dur, connectudp.DefaultBenchUDPPayloadLen)
	_ = echoPkt.Close()
	if err != nil {
		t.Fatalf("echo-duplex: %v", err)
	}

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

	ratio := echoMbps / fountainMbps
	t.Logf("LOCALIZE h2 echo-duplex gap: fountain=%.1f echo=%.1f ratio=%.2f (want ratio>=0.75 when fountain>=400)",
		fountainMbps, echoMbps, ratio)
	if fountainMbps >= 400 && ratio < 0.75 {
		inttestLocalizeEchoDuplexGateFail(t, "h2 echo-duplex %.1f Mbit/s < 75%% of fountain %.1f — H2 bidi capsule contention", echoMbps, fountainMbps)
	}
}
