package masque

// Inttest synth localize runners (W-UDP-4 UDP-STRUCT-02 MOVE).

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"testing"
	"time"

	"github.com/sagernet/sing-box/transport/masque/connectudp"
	h2c "github.com/sagernet/sing-box/transport/masque/h2"
	M "github.com/sagernet/sing/common/metadata"
)

// TestLocalizeConnectUDPH2UploadMaxCapsule logs upload at max RFC9297 DATAGRAM payload.
// FAIL when path ceiling is clearly below DoD track (~650+ Mbit/s on instant link; prior good run ~750).
func InttestLocalizeConnectUDPH2UploadMaxCapsule(t *testing.T) {
	t.Helper()
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
func InttestLocalizeConnectUDPH2UploadMaxCapsuleDirectDial(t *testing.T) {
	t.Helper()
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

// TestGATEConnectUDPH2SynthProdDownload locks connect-udp-h2 prod S2C fountain on instant link (synth >= 500 Mbit/s).
// Echo-duplex on a single HTTP/2 CONNECT stream is capped by bidi contention — see TestLocalizeConnectUDPH2EchoDuplexGapWithFountain.

// TestLocalizeConnectUDPH3DuplexEcho logs upload-only vs echo-duplex download on instant link.
// Localization only — does not FAIL on OPEN ceiling; use to confirm C2S echo contention vs upload-only.
func InttestLocalizeConnectUDPH3DuplexEcho(t *testing.T) {
	t.Helper()
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
func InttestLocalizeConnectUDPH3DownloadPipelineDepth(t *testing.T) {
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



// TestLocalizeConnectUDPH3DownloadFountain logs S2C-only receive (server UDP flood after prime).
func InttestLocalizeConnectUDPH3DownloadFountain(t *testing.T) {
	t.Helper()
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
	_, mbps, err := benchConnectUDPH3FountainS2C(t, pkt, fountainAddr, dur, connectudp.DefaultBenchUDPPayloadLen, false)
	if err != nil {
		t.Fatalf("receive-only: %v", err)
	}
	t.Logf("LOCALIZE connect-udp-h3 download fountain-flood (S2C-only): %.1f Mbit/s", mbps)
	if !synthInstantDownloadGatePass(mbps) {
		t.Logf("OPEN: S2C-only below synth gate — receive/datagram path ceiling, not echo contention")
	}
}



// InttestLocalizeConnectUDPH2EchoDuplexAsymmetricVsBidi compares prod asymmetric legs vs legacy bidi dial (UDP-AUDIT-11).
func InttestLocalizeConnectUDPH2EchoDuplexAsymmetricVsBidi(t *testing.T) {
	t.Skip("HP-2d: non-asymmetric H2 CONNECT-UDP dial CUT — prod is asymmetric-only")
}



// TestLocalizeConnectUDPH2DownloadPipelineDepth logs echo-duplex download vs in-flight C2S depth (H2).
func InttestLocalizeConnectUDPH2DownloadPipelineDepth(t *testing.T) {
	t.Helper()
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
func InttestLocalizeConnectUDPH3Pipeline1ProdShape(t *testing.T) {
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
func InttestLocalizeConnectUDPH2Pipeline1ProdShape(t *testing.T) {
	t.Helper()
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
func InttestLocalizeConnectUDPH2EchoPipeline256VsUnlimited(t *testing.T) {
	t.Helper()
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
func InttestLocalizeConnectUDPH2DownloadFountain(t *testing.T) {
	t.Helper()
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
	_, mbps, err := benchConnectUDPFountainS2C(t, pkt, fountainAddr, dur, connectudp.DefaultBenchUDPPayloadLen, false)
	if err != nil {
		t.Fatalf("fountain receive: %v", err)
	}
	t.Logf("LOCALIZE connect-udp-h2 download fountain-flood (S2C-only): %.1f Mbit/s", mbps)
	if !synthInstantGatePass(mbps) {
		t.Fatalf("%s", synthKPIDiagnostic("L4 connect-udp-h2 prod", "udp_down_fountain", mbps, connectUDPSynthInstantMinMbps,
			"S2C-only fountain — inline downlink scan / server relay ceiling"))
	}
}



// TestLocalizeConnectUDPH2DownloadFountainMaxCapsule logs S2C fountain at max RFC9297 capsule payload.
func InttestLocalizeConnectUDPH2DownloadFountainMaxCapsule(t *testing.T) {
	t.Helper()
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
	_, mbps, err := benchConnectUDPFountainS2C(t, pkt, fountainAddr, dur, maxPayload, false)
	if err != nil {
		t.Fatalf("fountain receive max capsule: %v", err)
	}
	t.Logf("LOCALIZE connect-udp-h2 fountain maxCapsule(%dB): %.1f Mbit/s", maxPayload, mbps)
}



// TestLocalizeConnectUDPH2DownloadFountainPayloadScaling checks whether H2 S2C fountain is
// per-datagram decode bound (weak ratio) vs wire bandwidth bound.
func InttestLocalizeConnectUDPH2DownloadFountainPayloadScaling(t *testing.T) {
	t.Helper()
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
		_, mbps, err := benchConnectUDPFountainS2C(t, pkt, fountainAddr, dur, payloadLen, false)
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
func InttestLocalizeConnectUDPH2UploadPayloadScaling(t *testing.T) {
	t.Helper()
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

// InttestLocalizeConnectUDPH3UploadPayloadScaling checks whether H3 upload is PPS/datagram-bound (UDP-5p1).
func InttestLocalizeConnectUDPH3UploadPayloadScaling(t *testing.T) {
	t.Helper()
	dur := connectUDPSynthProdBenchDuration
	_, mbps512, err := benchConnectUDPProdProfileH3Upload(t, instantDatagramLink{}, dur, 0, connectudp.DefaultBenchUDPPayloadLen)
	if err != nil {
		t.Fatalf("h3 upload 512B: %v", err)
	}
	steady := connectudp.SteadyUploadPayloadLenH3()
	_, mbpsSteady, err := benchConnectUDPProdProfileH3Upload(t, instantDatagramLink{}, dur, 0, steady)
	if err != nil {
		t.Fatalf("h3 upload steady(%dB): %v", steady, err)
	}
	ratio := mbpsSteady / mbps512
	t.Logf("LOCALIZE h3 upload payload scaling: 512B=%.1f steady(%dB)=%.1f ratio=%.2f",
		mbps512, steady, mbpsSteady, ratio)
	const minRatio = 1.15
	if mbps512 >= 200 && ratio < minRatio {
		t.Fatalf("h3 upload weak payload scaling (512=%.1f steady=%.1f ratio=%.2f) — PPS/datagram tax (UDP-5p1)",
			mbps512, mbpsSteady, ratio)
	}
}

// InttestLocalizeConnectUDPH2UploadVsConnectStreamAnchor compares H2 CONNECT-UDP upload with
// connect-stream upload on the same in-proc H2 proxy + SOCKS path. FAIL when stream is fast
// but UDP upload is structurally capped (wire ceiling), not when both legs are slow.
func InttestLocalizeConnectUDPH2UploadVsConnectStreamAnchor(t *testing.T) {
	t.Helper()
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


// TestLocalizeConnectUDPH2UploadVsConnectStreamSameWriteSize compares CONNECT-UDP with connect-stream
// when both use DefaultBenchUDPPayloadLen (512 B) writes — separates bench write-size skew from capsule wire path.
func InttestLocalizeConnectUDPH2UploadVsConnectStreamSameWriteSize(t *testing.T) {
	t.Helper()
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



// TestLocalizeConnectUDPH2UploadDirectDialVsListenPacket compares dialUDPOverHTTP2 (client.DialAddr H2 leg)
// with prod ListenPacket. FAIL when session wrapper is the bottleneck.
func InttestLocalizeConnectUDPH2UploadDirectDialVsListenPacket(t *testing.T) {
	t.Helper()
	dur := connectUDPSynthProdBenchDuration
	_, directMbps, err := benchConnectUDPH2OverlayDirectUpload(t, instantH2Link{}, dur, connectudp.DefaultBenchUDPPayloadLen)
	if err != nil {
		t.Fatalf("h2 overlay direct upload: %v", err)
	}
	_, listenMbps, err := benchConnectUDPProdProfileH2UploadViaListenPacket(t, instantH2Link{}, dur, 0, connectudp.DefaultBenchUDPPayloadLen)
	if err != nil {
		t.Fatalf("h2 ListenPacket upload: %v", err)
	}
	ratio := directMbps / listenMbps
	t.Logf("LOCALIZE h2 direct overlay vs ListenPacket upload: direct=%.1f listen=%.1f ratio=%.2f (want 0.85–1.15 when listen>=300)",
		directMbps, listenMbps, ratio)
	if listenMbps >= 300 && (ratio < 0.85 || ratio > 1.15) {
		t.Fatalf("ListenPacket vs dialUDPOverHTTP2 upload gap (direct=%.1f listen=%.1f ratio=%.2f) — session/wrapper overhead or divergent wire path",
			directMbps, listenMbps, ratio)
	}
}



// TestLocalizeConnectUDPH2DownloadFountainDirectDialVsListenPacket compares dialUDPOverHTTP2 fountain
// S2C with prod ListenPacket. FAIL when DatagramSplitConn/session is the download bottleneck.
// ListenPacket runs first so a prior direct-dial flood does not starve the wrapper path.
func InttestLocalizeConnectUDPH2DownloadFountainDirectDialVsListenPacket(t *testing.T) {
	t.Helper()
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
	_, listenMbps, err := benchConnectUDPFountainS2C(t, pkt, fountainAddr, dur, connectudp.DefaultBenchUDPPayloadLen, false)
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
		t.Fatalf("ListenPacket vs dialUDPOverHTTP2 fountain gap (direct=%.1f listen=%.1f ratio=%.2f) — session/wrapper overhead or divergent wire path",
			directMbps, listenMbps, ratio)
	}
}



// TestLocalizeConnectUDPH2UploadBulkFlushTLSFlushTax verifies bulk TLS flush raises H2 upload
// when each TCP write carries docker-shaped flush latency (synth before docker).
func InttestLocalizeConnectUDPH2UploadBulkFlushTLSFlushTax(t *testing.T) {
	t.Helper()
	const dur = connectUDPSynthProdBenchDuration
	link := tlsFlushTaxH2Link{Tax: 8 * time.Microsecond}

	t.Setenv("MASQUE_H2_CONNECT_UPLOAD_BULK_FLUSH", "0")
	_, offMbps, err := benchConnectUDPProdProfileH2Upload(t, link, dur, 0, connectudp.DefaultBenchUDPPayloadLen)
	if err != nil {
		t.Fatalf("bulk flush off: %v", err)
	}
	t.Setenv("MASQUE_H2_CONNECT_UPLOAD_BULK_FLUSH", "1")
	_, onMbps, err := benchConnectUDPProdProfileH2Upload(t, link, dur, 0, connectudp.DefaultBenchUDPPayloadLen)
	if err != nil {
		t.Fatalf("bulk flush on: %v", err)
	}
	ratio := onMbps / offMbps
	t.Logf("LOCALIZE h2 bulk flush tls-tax: off=%.1f on=%.1f ratio=%.2f (docker bisect; ratio>1 expected on flush-tax link)", offMbps, onMbps, ratio)
	if offMbps > 200 && onMbps < offMbps*0.90 {
		t.Fatalf("bulk TLS flush regression on flush-tax link: off=%.1f on=%.1f", offMbps, onMbps)
	}
}



// TestLocalizeConnectUDPH2UploadDockerTlsTaxSweep calibrates tlsFlushTaxH2Link against docker ~375 Mbit/s ceiling.
// Logs mbps at each tax; instant link must stay >= synth gate; tax sweep localizes docker-shaped wire budget.
func InttestLocalizeConnectUDPH2UploadDockerTlsTaxSweep(t *testing.T) {
	t.Helper()
	const dur = connectUDPSynthProdBenchDuration
	_, instantMbps, err := benchConnectUDPProdProfileH2Upload(t, instantH2Link{}, dur, 0, connectudp.DefaultBenchUDPPayloadLen)
	if err != nil {
		t.Fatalf("instant link: %v", err)
	}
	if !synthInstantGatePass(instantMbps) {
		t.Fatalf("instant h2 upload %.1f < synth gate %.0f", instantMbps, connectUDPSynthInstantMinMbps)
	}
	for _, taxUs := range []int{2, 4, 6, 8, 10, 12, 16, 20, 24, 32} {
		link := tlsFlushTaxH2Link{Tax: time.Duration(taxUs) * time.Microsecond}
		_, mbps, err := benchConnectUDPProdProfileH2Upload(t, link, dur, 0, connectudp.DefaultBenchUDPPayloadLen)
		if err != nil {
			t.Fatalf("tax=%dus: %v", taxUs, err)
		}
		t.Logf("LOCALIZE h2 upload tls-tax=%dus/4KiB-rec: %.1f Mbit/s (instant=%.1f docker-h2~170 docker-h3~375)", taxUs, mbps, instantMbps)
	}
}
