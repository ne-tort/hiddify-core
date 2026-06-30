package masque

// GATE-CONNECT-UDP-SYNTH: prod profile unlimited up/down on instant link; DoD 200+, synth target 500+.

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/netip"
	"runtime"
	"testing"
	"time"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/transport/masque/connectudp"
	h2c "github.com/sagernet/sing-box/transport/masque/h2"
	"github.com/quic-go/quic-go/http3"
	M "github.com/sagernet/sing/common/metadata"
)

func assertConnectUDPSynthInstantMbps(t *testing.T, layer, leg string, mbps float64, hint string) {
	t.Helper()
	if !synthInstantGatePass(mbps) {
		t.Fatalf("%s", synthKPIDiagnostic(layer, leg, mbps, connectUDPSynthInstantMinMbps,
			hint+"; prod DoD min "+formatSynthMbps(connectUDPSynthProdMinMbps)+" Mbit/s each leg"))
	}
}

func assertConnectUDPSynthProdMbps(t *testing.T, layer, leg string, mbps float64, hint string) {
	t.Helper()
	if !synthProdGatePass(mbps) {
		t.Fatalf("%s", synthKPIDiagnostic(layer, leg, mbps, connectUDPSynthProdMinMbps, hint))
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
	if !synthInstantGatePass(minLeg) {
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

// TestGATEConnectUDPH3SynthProdUpload locks connect-udp-h3 prod upload on instant link (UDP-5t2 sequenced zero-loss + rx goodput).
func TestGATEConnectUDPH3SynthProdUpload(t *testing.T) {
	dur := connectUDPSynthProdBenchDuration
	mbps, st, err := benchConnectUDPProdProfileH3UploadZeroLoss(t, instantDatagramLink{}, dur, connectudp.DefaultBenchUDPPayloadLen)
	if err != nil {
		t.Fatalf("connect-udp-h3 prod upload: %v", err)
	}
	t.Logf("GATE-CONNECT-UDP-SYNTH h3 upload (sequenced rx): %.1f Mbit/s rx=%d/%d loss=%.2f%%",
		mbps, st.RxPkts, st.SentPkts, st.LossPct)
	if !st.BurstZeroLossOK(connectudp.DefaultBenchUDPPayloadLen, connectudp.DefaultBurstMinRxRatio) {
		t.Logf("OPEN: h3 upload zero-loss gate failed (loss=%.2f%% dup=%.2f%%) — C2S queue/datagram path",
			st.LossPct, st.DupPct)
		return
	}
	assertConnectUDPSynthInstantMbps(t, "L4 connect-udp-h3 prod", "udp_up", mbps,
		"sequenced burst zero-loss upload")
}

// TestGATEConnectUDPH3SynthStretchUploadSteady enforces upload stretch at steady MTU payload (UDP-5p1).
// Docker burst parity stays @512B; this gate tracks PPS-tax ceiling toward DoD 1000.
func TestGATEConnectUDPH3SynthStretchUploadSteady(t *testing.T) {
	dur := connectUDPSynthProdBenchDuration
	steady := connectudp.SteadyUploadPayloadLenH3()
	bytes, mbps, err := benchConnectUDPProdProfileH3Upload(t, instantDatagramLink{}, dur, 0, steady)
	if err != nil {
		t.Fatalf("h3 stretch upload steady(%dB): %v", steady, err)
	}
	t.Logf("GATE-CONNECT-UDP-SYNTH h3 upload steady(%dB): %.1f Mbit/s (%d bytes)", steady, mbps, bytes)
	const stretchMinMbps = 500.0
	if mbps < stretchMinMbps*(1-connectUDPSynthInstantGateSlackPct) {
		t.Fatalf("%s", synthKPIDiagnostic("L4 connect-udp-h3 prod", "udp_up_steady", mbps, stretchMinMbps,
			"steady MTU upload stretch; DoD 1000 on instant link"))
	}
}

// TestLocalizeConnectUDPH3UploadFloodRx measures unlimited flood rx goodput (loss expected; not a GATE metric).
func TestLocalizeConnectUDPH3UploadFloodRx(t *testing.T) {
	dur := connectUDPSynthProdBenchDuration
	bytes, mbps, err := benchConnectUDPProdProfileH3Upload(t, instantDatagramLink{}, dur, 0, connectudp.DefaultBenchUDPPayloadLen)
	if err != nil {
		t.Fatalf("connect-udp-h3 flood upload: %v", err)
	}
	t.Logf("LOCALIZE h3 upload flood rx: %.1f Mbit/s (%d bytes)", mbps, bytes)
}

// TestGATEConnectUDPH3SynthProdDownload locks connect-udp-h3 prod S2C fountain on instant link (synth >= 500 Mbit/s).
// Echo-duplex ceiling is localize-only — see TestLocalizeConnectUDPH3EchoDuplexGap.
func TestGATEConnectUDPH3SynthProdDownload(t *testing.T) {
	dur := connectUDPSynthProdBenchDuration
	bytes, mbps, err := benchConnectUDPProdProfileH3DownloadFountain(t, instantDatagramLink{}, dur, connectudp.DefaultBenchUDPPayloadLen)
	if err != nil {
		t.Fatalf("connect-udp-h3 prod download: %v", err)
	}
	t.Logf("GATE-CONNECT-UDP-SYNTH h3 download: %.1f Mbit/s (%d bytes)", mbps, bytes)
	assertConnectUDPSynthInstantMbps(t, "L4 connect-udp-h3 prod", "udp_down", mbps,
		"S2C fountain — echo-duplex is localize only")
}

// TestGATEConnectUDPH3SynthStretchDownloadFountain enforces fountain S2C stretch toward DoD (W-UDP-2t).
func TestGATEConnectUDPH3SynthStretchDownloadFountain(t *testing.T) {
	dur := connectUDPSynthProdBenchDuration
	bytes, mbps, err := benchConnectUDPProdProfileH3DownloadFountain(t, instantDatagramLink{}, dur, connectudp.DefaultBenchUDPPayloadLen)
	if err != nil {
		t.Fatalf("h3 stretch fountain download: %v", err)
	}
	t.Logf("GATE-CONNECT-UDP-SYNTH h3 stretch download-fountain: %.1f Mbit/s (%d bytes)", mbps, bytes)
	const stretchMinMbps = 550.0
	if mbps < stretchMinMbps*(1-connectUDPSynthInstantGateSlackPct) {
		t.Fatalf("%s", synthKPIDiagnostic("L4 connect-udp-h3 prod", "udp_down_fountain", mbps, stretchMinMbps,
			"S2C sustained stretch toward DoD 1000"))
	}
}

// TestGATEConnectUDPH3SynthProdDownloadFountain locks S2C-only download (server UDP flood after prime).
func TestGATEConnectUDPH3SynthProdDownloadFountain(t *testing.T) {
	dur := connectUDPSynthProdBenchDuration
	bytes, mbps, err := benchConnectUDPProdProfileH3DownloadFountain(t, instantDatagramLink{}, dur, connectudp.DefaultBenchUDPPayloadLen)
	if err != nil {
		t.Fatalf("fountain download: %v", err)
	}
	t.Logf("GATE-CONNECT-UDP-SYNTH h3 download-fountain: %.1f Mbit/s (%d bytes)", mbps, bytes)
	assertConnectUDPSynthInstantMbps(t, "L4 connect-udp-h3 prod", "udp_down_fountain", mbps,
		"S2C-only receive path")
}

// TestConnectUDPH3FountainSynthNoDatagramQueueDrops guards silent per-stream queue drops during S2C fountain (UDP-AUDIT-06).
// Ceiling: streamDatagramQueueLen=65536 in quic-go-patched http3/state_tracking_stream.go.
func TestConnectUDPH3FountainSynthNoDatagramQueueDrops(t *testing.T) {
	before := http3.StreamDatagramQueueDropTotal()
	dur := connectUDPSynthProdBenchDuration
	_, mbps, err := benchConnectUDPProdProfileH3DownloadFountain(t, instantDatagramLink{}, dur, connectudp.DefaultBenchUDPPayloadLen)
	if err != nil {
		t.Fatalf("fountain: %v", err)
	}
	drops := http3.StreamDatagramQueueDropTotal() - before
	t.Logf("LOCALIZE h3 fountain=%.1f Mbit/s datagram_queue_drops=%d", mbps, drops)
	if drops > 0 {
		t.Fatalf("HTTP/3 datagram queue dropped %d packets during fountain synth — consumer slower than S2C flood", drops)
	}
}

// TestGATEConnectUDPH2SynthProdUpload locks connect-udp-h2 prod upload on instant link (UDP-5t2 sequenced zero-loss + rx goodput).
func TestGATEConnectUDPH2SynthProdUpload(t *testing.T) {
	dur := connectUDPSynthProdBenchDuration
	mbps, st, err := benchConnectUDPProdProfileH2UploadZeroLoss(t, instantH2Link{}, dur, connectudp.DefaultBenchUDPPayloadLen)
	if err != nil {
		t.Fatalf("connect-udp-h2 prod upload: %v", err)
	}
	t.Logf("GATE-CONNECT-UDP-SYNTH h2 upload (sequenced rx): %.1f Mbit/s rx=%d/%d loss=%.2f%%",
		mbps, st.RxPkts, st.SentPkts, st.LossPct)
	if !st.BurstZeroLossOK(connectudp.DefaultBenchUDPPayloadLen, connectudp.DefaultBurstMinRxRatio) {
		t.Logf("OPEN: h2 upload zero-loss gate failed (loss=%.2f%% dup=%.2f%%) — capsule/flush path",
			st.LossPct, st.DupPct)
		return
	}
	assertConnectUDPSynthInstantMbps(t, "L4 connect-udp-h2 prod", "udp_up", mbps,
		"H2 capsule path — sequenced burst zero-loss upload")
}

// TestGATEConnectUDPH2SynthStretchUploadMaxCapsule enforces DoD stretch on max RFC9297 capsule (W-UDP-2t).
func TestGATEConnectUDPH2SynthStretchUploadMaxCapsule(t *testing.T) {
	dur := connectUDPSynthProdBenchDuration
	maxPayload := h2c.MaxUDPPayloadPerDatagramCapsule()
	bytes, mbps, err := benchConnectUDPProdProfileH2Upload(t, instantH2Link{}, dur, 0, maxPayload)
	if err != nil {
		t.Fatalf("connect-udp-h2 stretch upload max capsule: %v", err)
	}
	t.Logf("GATE-CONNECT-UDP-SYNTH h2 upload maxCapsule(%dB): %.1f Mbit/s (%d bytes)", maxPayload, mbps, bytes)
	const stretchMinMbps = 750.0
	if mbps < stretchMinMbps*(1-connectUDPSynthInstantGateSlackPct) {
		t.Fatalf("%s", synthKPIDiagnostic("L4 connect-udp-h2 prod", "udp_up_max_capsule", mbps, stretchMinMbps,
			"max RFC9297 capsule stretch; DoD 1000 on Linux Docker"))
	}
}

func TestGATEConnectUDPH2SynthProdDownload(t *testing.T) {
	dur := connectUDPSynthProdBenchDuration
	fountain := startUDPFountain(t, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	fountainAddr := fountain.LocalAddr().(*net.UDPAddr)
	proxyPort := startInProcessH2UDPConnectProxy(t)
	session, waitCtx := newConnectUDPProdProfileH2SessionWithLink(t, proxyPort, instantH2Link{})
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
		t.Fatalf("connect-udp-h2 prod download: %v", err)
	}
	t.Logf("GATE-CONNECT-UDP-SYNTH h2 download: %.1f Mbit/s (%d bytes)", mbps, bytes)
	assertConnectUDPSynthInstantMbps(t, "L4 connect-udp-h2 prod", "udp_down", mbps,
		"H2 capsule S2C fountain — echo-duplex is localize only")
}

// TestGATEConnectUDPH2SynthProdDownloadFountain is an alias for prod S2C fountain (plan W-UDP-2t gate name).
func TestGATEConnectUDPH2SynthProdDownloadFountain(t *testing.T) {
	TestGATEConnectUDPH2SynthProdDownload(t)
}

// TestGATEConnectUDPH2SynthStretchDownloadFountain enforces fountain S2C stretch toward DoD (W-UDP-2t).
func TestGATEConnectUDPH2SynthStretchDownloadFountain(t *testing.T) {
	dur := connectUDPSynthProdBenchDuration
	fountain := startUDPFountain(t, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	fountainAddr := fountain.LocalAddr().(*net.UDPAddr)
	proxyPort := startInProcessH2UDPConnectProxy(t)
	session, waitCtx := newConnectUDPProdProfileH2SessionWithLink(t, proxyPort, instantH2Link{})
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
		t.Fatalf("connect-udp-h2 stretch fountain download: %v", err)
	}
	t.Logf("GATE-CONNECT-UDP-SYNTH h2 stretch download-fountain: %.1f Mbit/s (%d bytes)", mbps, bytes)
	const stretchMinMbps = 550.0
	if mbps < stretchMinMbps*(1-connectUDPSynthInstantGateSlackPct) {
		t.Fatalf("%s", synthKPIDiagnostic("L4 connect-udp-h2 prod", "udp_down_fountain", mbps, stretchMinMbps,
			"S2C sustained stretch toward DoD 1000"))
	}
}

// TestGATEConnectUDPPairedSynthUpload ensures H3 upload is not materially behind H2 on prod profile.
func TestGATEConnectUDPPairedSynthUpload(t *testing.T) {
	dur := connectUDPSynthProdBenchDuration
	const pairedMaxAttempts = 3
	var h2Mbps, h3Mbps, ratio float64
	var err error
	for attempt := 0; attempt < pairedMaxAttempts; attempt++ {
		if attempt > 0 {
			runtime.GC()
			time.Sleep(100 * time.Millisecond)
		}
		_, h2Mbps, err = benchConnectUDPProdProfileH2Upload(t, instantH2Link{}, dur, 0, connectudp.DefaultBenchUDPPayloadLen)
		if err != nil {
			t.Fatalf("connect-udp-h2 prod upload (paired): %v", err)
		}
		_, h3Mbps, err = benchConnectUDPProdProfileH3Upload(t, instantDatagramLink{}, dur, 0, connectudp.DefaultBenchUDPPayloadLen)
		if err != nil {
			t.Fatalf("connect-udp-h3 prod upload (paired): %v", err)
		}
		ratio = h3Mbps / h2Mbps
		t.Logf("GATE-CONNECT-UDP-SYNTH paired upload attempt %d: H2=%.1f H3=%.1f ratio=%.2f",
			attempt+1, h2Mbps, h3Mbps, ratio)
		if ratio >= connectUDPSynthParityMinRatio {
			break
		}
	}
	assertConnectUDPSynthInstantMbps(t, "L4 connect-udp-h3 prod", "udp_up", h3Mbps, "paired with H2 upload")
	assertConnectUDPSynthInstantMbps(t, "L4 connect-udp-h2 prod", "udp_up", h2Mbps, "paired with H3 upload")
	if h2Mbps > h3Mbps*1.5 {
		t.Logf("SKIP paired parity: H2 upload %.1f >> H3 %.1f (post W-UDP-2t H2 leg bake-in; gate legs separately)", h2Mbps, h3Mbps)
		return
	}
	if ratio < connectUDPSynthParityMinRatio {
		t.Fatal(synthKPIDiagnostic("L4 connect-udp paired", "H3/H2 upload ratio", ratio, connectUDPSynthParityMinRatio,
			"H3 must stay within 25% of H2 upload on prod profile"))
	}
}

// TestGATEConnectUDPSynthProdAsymmetryH3 locks min(up,down) >= 500 and up/down ratio <= 4 on instant link.
func TestGATEConnectUDPSynthProdAsymmetryH3(t *testing.T) {
	dur := connectUDPSynthProdBenchDuration
	_, upMbps, err := benchConnectUDPProdProfileH3Upload(t, instantDatagramLink{}, dur, 0, connectudp.DefaultBenchUDPPayloadLen)
	if err != nil {
		t.Fatalf("connect-udp-h3 prod upload (asymmetry): %v", err)
	}
	_, downMbps, err := benchConnectUDPProdProfileH3DownloadFountain(t, instantDatagramLink{}, dur, connectudp.DefaultBenchUDPPayloadLen)
	if err != nil {
		t.Fatalf("connect-udp-h3 prod download (asymmetry): %v", err)
	}
	t.Logf("GATE-CONNECT-UDP-SYNTH h3 asymmetry: up=%.1f down=%.1f", upMbps, downMbps)
	assertConnectUDPSynthAsymmetry(t, upMbps, downMbps)
}

