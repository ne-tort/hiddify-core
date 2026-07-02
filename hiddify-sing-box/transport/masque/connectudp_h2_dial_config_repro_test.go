package masque

import (
	"context"
	"net"
	"net/netip"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	cudph2 "github.com/sagernet/sing-box/transport/masque/connectudp/h2"
	h2c "github.com/sagernet/sing-box/transport/masque/h2"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/yosida95/uritemplate/v3"
	"golang.org/x/net/http2"
)

func integrationShapedH2OverlayDialConfig(tb testing.TB, proxyPort int) cudph2.H2OverlayDialConfig {
	tb.Helper()
	clientTLS := connectUDPTestTLS.Clone()
	clientTLS.InsecureSkipVerify = true
	clientTLS.ServerName = "127.0.0.1"
	dialCfg := h2c.ClientDialConfig{
		TLSConfig:          clientTLS,
		DialHostCandidates: []string{""},
		TCPDial: func(ctx context.Context, network, addr string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, addr)
		},
	}
	tr, err := h2c.NewClientTransport(dialCfg)
	if err != nil {
		tb.Fatalf("integration-shaped transport: %v", err)
	}
	return cudph2.H2OverlayDialConfig{
		EnsureTransport: func(context.Context) (*http2.Transport, error) { return tr, nil },
		NewTransport:    func() (*http2.Transport, error) { return h2c.NewClientTransport(dialCfg) },
		ResolveDialAddr: func() string {
			return net.JoinHostPort("127.0.0.1", strconv.Itoa(proxyPort))
		},
	}
}

func burstH2MaxCapsuleUpload(tb testing.TB, pc net.PacketConn, maxPayload int) (sent, delivered int64) {
	tb.Helper()
	payload := make([]byte, maxPayload)
	var rx atomic.Int64
	go func() {
		buf := make([]byte, 65535)
		for {
			n, _, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			if n > 0 {
				rx.Add(int64(n))
			}
		}
	}()
	baseline := rx.Load()
	deadline := time.Now().Add(400 * time.Millisecond)
	for time.Now().Before(deadline) {
		nw, err := pc.WriteTo(payload, nil)
		if err != nil {
			tb.Fatalf("WriteTo: %v", err)
		}
		if nw != maxPayload {
			tb.Fatalf("short write: %d", nw)
		}
		sent += int64(maxPayload)
	}
	return sent, rx.Load() - baseline
}

func dialH2OverlayMaxCapsule(tb testing.TB, cfg cudph2.H2OverlayDialConfig, proxyPort int, sinkPort int) net.PacketConn {
	tb.Helper()
	rawTpl := "https://127.0.0.1:" + strconv.Itoa(proxyPort) + "/masque/udp/{target_host}/{target_port}"
	tpl, err := uritemplate.New(rawTpl)
	if err != nil {
		tb.Fatalf("template: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	tb.Cleanup(cancel)
	target := net.JoinHostPort("127.0.0.1", strconv.Itoa(sinkPort))
	pc, err := cudph2.DialH2Overlay(ctx, cfg, tpl, target)
	if err != nil {
		tb.Fatalf("DialH2Overlay: %v", err)
	}
	tb.Cleanup(func() { _ = pc.Close() })
	return pc
}

// TestH2MaxCapsuleIntegrationVsSessionDialConfig isolates max-capsule deadlock to overlay dial config.
func TestH2MaxCapsuleIntegrationVsSessionDialConfig(t *testing.T) {
	maxPayload := h2c.MaxUDPPayloadPerDatagramCapsule()
	sink, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("sink: %v", err)
	}
	t.Cleanup(func() { _ = sink.Close() })
	sinkPort := sink.LocalAddr().(*net.UDPAddr).Port
	go func() {
		buf := make([]byte, 65535)
		for {
			n, raddr, rerr := sink.ReadFrom(buf)
			if rerr != nil {
				return
			}
			_, _ = sink.WriteTo(buf[:n], raddr)
		}
	}()

	proxyPort := startInProcessH2UDPConnectProxy(t)

	t.Run("integration_shaped", func(t *testing.T) {
		cfg := integrationShapedH2OverlayDialConfig(t, proxyPort)
		pc := dialH2OverlayMaxCapsule(t, cfg, proxyPort, sinkPort)
		sent, delivered := burstH2MaxCapsuleUpload(t, pc, maxPayload)
		if delivered == 0 {
			t.Fatalf("integration-shaped: delivered 0 (sent~%d)", sent)
		}
		t.Logf("integration-shaped: sent~%d delivered=%d", sent, delivered)
	})

	t.Run("session_shaped", func(t *testing.T) {
		session, waitCtx := newConnectUDPProdProfileH2SessionWithLink(t, proxyPort, instantH2Link{})
		cs, ok := session.(*coreSession)
		if !ok {
			t.Fatalf("need *coreSession, got %T", session)
		}
		cs.Mu.Lock()
		tpl := cs.TemplateUDP
		cs.Mu.Unlock()
		target := net.JoinHostPort("127.0.0.1", strconv.Itoa(sinkPort))
		pc, err := cs.dialUDPOverHTTP2(waitCtx, tpl, target)
		if err != nil {
			t.Fatalf("dialUDPOverHTTP2: %v", err)
		}
		t.Cleanup(func() { _ = pc.Close() })
		done := make(chan struct{})
		var sent, delivered int64
		go func() {
			sent, delivered = burstH2MaxCapsuleUpload(t, pc, maxPayload)
			close(done)
		}()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("session-shaped max capsule burst hung")
		}
		if delivered == 0 {
			t.Fatalf("session-shaped: delivered 0 (sent~%d)", sent)
		}
		t.Logf("session-shaped: sent~%d delivered=%d", sent, delivered)
	})

	t.Run("listen_packet", func(t *testing.T) {
		session, waitCtx := newConnectUDPProdProfileH2SessionWithLink(t, proxyPort, instantH2Link{})
		sinkAddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: sinkPort}
		pkt, err := session.ListenPacket(waitCtx, M.Socksaddr{
			Addr: netip.MustParseAddr(sinkAddr.IP.String()),
			Port: uint16(sinkAddr.Port),
		})
		if err != nil {
			t.Fatalf("ListenPacket: %v", err)
		}
		t.Cleanup(func() { _ = pkt.Close() })
		done := make(chan struct{})
		var sent, delivered int64
		go func() {
			sent, delivered = burstH2MaxCapsuleUpload(t, pkt, maxPayload)
			close(done)
		}()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("ListenPacket max capsule burst hung")
		}
		if delivered == 0 {
			t.Fatalf("ListenPacket: delivered 0 (sent~%d)", sent)
		}
		t.Logf("ListenPacket: sent~%d delivered=%d", sent, delivered)
	})

	t.Run("bench_sink_3s_direct", func(t *testing.T) {
		sink, sinkRx := runUDPSink(t, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
		sinkAddr := sink.LocalAddr().(*net.UDPAddr)
		proxyPort := startInProcessH2UDPConnectProxy(t)
		session, waitCtx := newConnectUDPProdProfileH2SessionWithLink(t, proxyPort, instantH2Link{})
		cs := session.(*coreSession)
		cs.Mu.Lock()
		tpl := cs.TemplateUDP
		cs.Mu.Unlock()
		target := net.JoinHostPort(sinkAddr.IP.String(), strconv.Itoa(sinkAddr.Port))
		pc, err := cs.dialUDPOverHTTP2(waitCtx, tpl, target)
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		defer func() { _ = pc.Close() }()
		done := make(chan struct{})
		go func() {
			_, _, _ = benchConnectUDPPacketUpload(t, pc, sinkAddr, 3*time.Second, 0, maxPayload, sinkRx, true)
			close(done)
		}()
		select {
		case <-done:
		case <-time.After(8 * time.Second):
			t.Fatal("bench_sink_3s direct dial hung")
		}
	})
}
