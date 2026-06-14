package masque

// H-C bisect: masque.Endpoint + CM.Runtime + SOCKS fake iperf (connect-stream-h2 docker shape).

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/quic-go/quic-go/http3"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/masque/server"
	"github.com/sagernet/sing-box/route"
	TM "github.com/sagernet/sing-box/transport/masque"
	strm "github.com/sagernet/sing-box/transport/masque/stream"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/protocol/socks"
	"github.com/yosida95/uritemplate/v3"

	_ "github.com/sagernet/sing-box/internal/http2xconnect"
)

const endpointH2SocksFakeIperfMinBytes = 32 * 1024

type endpointH2SocksRouter struct {
	cm     *route.ConnectionManager
	dialer adapter.Outbound
}

func (r *endpointH2SocksRouter) RouteConnection(ctx context.Context, conn net.Conn, metadata adapter.InboundContext) error {
	done := make(chan struct{})
	r.RouteConnectionEx(ctx, conn, metadata, N.OnceClose(func(error) { close(done) }))
	<-done
	return nil
}

func (r *endpointH2SocksRouter) RouteConnectionEx(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	r.cm.NewConnection(ctx, r.dialer, conn, metadata, onClose)
}

func (r *endpointH2SocksRouter) RoutePacketConnection(ctx context.Context, conn N.PacketConn, metadata adapter.InboundContext) error {
	done := make(chan struct{})
	r.RoutePacketConnectionEx(ctx, conn, metadata, N.OnceClose(func(error) { close(done) }))
	<-done
	return nil
}

func (r *endpointH2SocksRouter) RoutePacketConnectionEx(ctx context.Context, conn N.PacketConn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	r.cm.NewPacketConnection(ctx, r.dialer, conn, metadata, onClose)
}

type endpointMasqueOutbound struct {
	outbound.Adapter
	ep *Endpoint
}

func (o *endpointMasqueOutbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	return o.ep.DialContext(ctx, network, destination)
}

func (o *endpointMasqueOutbound) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return o.ep.ListenPacket(ctx, destination)
}

func startEndpointH2ConnectStreamLaunchStack(t *testing.T) int {
	t.Helper()
	var tcpTemplate *uritemplate.Template
	mux := http.NewServeMux()
	mux.HandleFunc("/masque/tcp/{target_host}/{target_port}", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		if p := r.Header.Get(":protocol"); p != "" && p != strm.H2ConnectStreamProto {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		host := server.TCPConnectHost{
			Options: option.MasqueEndpointOptions{AllowPrivateTargets: true},
			Dialer:  net.Dialer{Timeout: 8 * time.Second},
			Authorize: func(*http.Request) bool {
				return true
			},
			AuthorityMatches: func(_, _ string, _ bool) bool { return true },
		}
		server.HandleTCPConnectRequest(host, w, r, tcpTemplate, true)
	})

	h3TLS := TM.InProcessH3TestTLS(t)
	h3TLS = h3TLS.Clone()
	h3TLS.NextProtos = []string{http3.NextProtoH3}
	collateralTLS := TM.InProcessH3TestTLS(t)
	collateralTLS = collateralTLS.Clone()
	collateralTLS.NextProtos = []string{"h2", "http/1.1"}

	stack, err := server.LaunchMasqueStack(server.LaunchMasqueStackConfig{
		Handler:       mux,
		ListenHost:    "127.0.0.1",
		ListenPort:    0,
		HTTP3TLS:      h3TLS,
		CollateralTLS: collateralTLS,
		ValidateUDP:   func(net.PacketConn) error { return nil },
	})
	if err != nil {
		t.Fatalf("LaunchMasqueStack: %v", err)
	}
	if stack == nil || stack.HTTP2Server == nil || stack.TCPTLSListener == nil {
		t.Fatal("expected HTTP/2 collateral listener on LaunchMasqueStack")
	}
	t.Cleanup(func() {
		if shutErr := server.ShutdownMasqueEndpoint(server.ShutdownMasqueEndpointConfig{Stack: stack}); shutErr != nil {
			t.Errorf("shutdown LaunchMasqueStack: %v", shutErr)
		}
	})

	tcpAddr, ok := stack.TCPTLSListener.Addr().(*net.TCPAddr)
	if !ok || tcpAddr == nil {
		t.Fatalf("unexpected TCP listener addr: %T", stack.TCPTLSListener.Addr())
	}
	port := tcpAddr.Port
	rawTpl := fmt.Sprintf("https://127.0.0.1:%d/masque/tcp/{target_host}/{target_port}", port)
	tcpTemplate, err = uritemplate.New(rawTpl)
	if err != nil {
		t.Fatalf("tcp template: %v", err)
	}
	time.Sleep(30 * time.Millisecond)
	return port
}

func startEndpointH2ConnectStreamSocksRouter(t *testing.T, ep *Endpoint) uint16 {
	t.Helper()
	out := &endpointMasqueOutbound{
		Adapter: outbound.NewAdapter(C.TypeMasque, "masque-ep", []string{N.NetworkTCP, N.NetworkUDP}, nil),
		ep:      ep,
	}
	cm := route.NewConnectionManager(log.StdLogger())
	t.Cleanup(func() { _ = cm.Close() })
	router := &endpointH2SocksRouter{cm: cm, dialer: out}
	upstream := adapter.NewRouteHandlerEx(adapter.InboundContext{
		Inbound:     "socks-in",
		InboundType: C.TypeSOCKS,
	}, router)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen socks: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	port := uint16(ln.Addr().(*net.TCPAddr).Port)
	go func() {
		for {
			conn, acceptErr := ln.Accept()
			if acceptErr != nil {
				return
			}
			go func(c net.Conn) {
				_ = socks.HandleConnectionEx(
					context.Background(),
					c,
					bufio.NewReader(c),
					nil,
					upstream,
					nil,
					C.UDPTimeout,
					M.SocksaddrFromNet(c.RemoteAddr()),
					nil,
				)
			}(conn)
		}
	}()
	time.Sleep(20 * time.Millisecond)
	return port
}

func waitEndpointReady(t *testing.T, ep *Endpoint) {
	t.Helper()
	deadline := time.Now().Add(12 * time.Second)
	for !ep.IsReady() && time.Now().Before(deadline) {
		if err := ep.lastStartError(); err != nil {
			t.Fatalf("endpoint startup failed: %v", err)
		}
		time.Sleep(25 * time.Millisecond)
	}
	if !ep.IsReady() {
		if err := ep.lastStartError(); err != nil {
			t.Fatalf("endpoint not ready: %v", err)
		}
		t.Fatal("endpoint not ready after timeout")
	}
}

// TestEndpointConnectStreamH2SocksFakeIperfNoPulse (H-C) — masque.Endpoint + CM.Runtime vs CoreClientFactory.
func TestEndpointConnectStreamH2SocksFakeIperfNoPulse(t *testing.T) {
	targetPort := TM.IntegrationStartH2FakeIperfDownloadTarget(t)
	proxyPort := startEndpointH2ConnectStreamLaunchStack(t)

	epRaw, err := NewEndpoint(context.Background(), nil, log.StdLogger(), "masque-h2", option.MasqueEndpointOptions{
		ServerOptions: option.ServerOptions{Server: "127.0.0.1", ServerPort: uint16(proxyPort)},
		HopPolicy:     option.MasqueHopPolicySingle,
		TransportMode: option.MasqueTransportModeConnectUDP,
		TCPTransport:  option.MasqueTCPTransportConnectStream,
		HTTPLayer:     option.MasqueHTTPLayerH2,
		TemplateTCP:   fmt.Sprintf("https://127.0.0.1:%d/masque/tcp/{target_host}/{target_port}", proxyPort),
		OutboundTLS: &option.OutboundTLSOptions{
			Enabled:    true,
			Insecure:   true,
			ServerName: "127.0.0.1",
		},
	})
	if err != nil {
		t.Fatalf("NewEndpoint: %v", err)
	}
	ep := epRaw.(*Endpoint)
	t.Cleanup(func() { _ = ep.Close() })
	if err := ep.Start(adapter.StartStatePostStart); err != nil {
		t.Fatalf("Start endpoint: %v", err)
	}
	waitEndpointReady(t, ep)

	socksPort := startEndpointH2ConnectStreamSocksRouter(t, ep)
	conn := TM.IntegrationSocksTCPDial(t, socksPort, targetPort)
	if err := conn.SetDeadline(time.Now().Add(12 * time.Second)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}

	banner := make([]byte, 8)
	if _, err := io.ReadFull(conn, banner); err != nil {
		t.Fatalf("read fake iperf banner: %v", err)
	}
	if string(banner) != "iperf3\r\n" {
		t.Fatalf("banner: got %q", string(banner))
	}
	if _, err := conn.Write([]byte("FAKEIPERF")); err != nil {
		t.Fatalf("write fake iperf params: %v", err)
	}

	var dst bytes.Buffer
	n, err := io.Copy(&dst, conn)
	if err != nil && n == 0 {
		t.Fatalf("fake iperf download: %v", err)
	}
	if n < endpointH2SocksFakeIperfMinBytes {
		t.Fatalf("fake iperf download short: %d want >= %d", n, endpointH2SocksFakeIperfMinBytes)
	}
	t.Logf("endpoint H2 SOCKS fake iperf no-pulse: %d bytes", n)
}

// TestEndpointConnectStreamH2WriteToOnlyIperfBanner (H2-R2) — masque.Endpoint + CM download-first
// WriteTo without client Read of banner first (docker iperf -R hang shape).
func TestEndpointConnectStreamH2WriteToOnlyIperfBanner(t *testing.T) {
	targetPort := TM.IntegrationStartH2FakeIperfDownloadTarget(t)
	proxyPort := startEndpointH2ConnectStreamLaunchStack(t)

	epRaw, err := NewEndpoint(context.Background(), nil, log.StdLogger(), "masque-h2", option.MasqueEndpointOptions{
		ServerOptions: option.ServerOptions{Server: "127.0.0.1", ServerPort: uint16(proxyPort)},
		HopPolicy:     option.MasqueHopPolicySingle,
		TransportMode: option.MasqueTransportModeConnectUDP,
		TCPTransport:  option.MasqueTCPTransportConnectStream,
		HTTPLayer:     option.MasqueHTTPLayerH2,
		TemplateTCP:   fmt.Sprintf("https://127.0.0.1:%d/masque/tcp/{target_host}/{target_port}", proxyPort),
		OutboundTLS: &option.OutboundTLSOptions{
			Enabled:    true,
			Insecure:   true,
			ServerName: "127.0.0.1",
		},
	})
	if err != nil {
		t.Fatalf("NewEndpoint: %v", err)
	}
	ep := epRaw.(*Endpoint)
	t.Cleanup(func() { _ = ep.Close() })
	if err := ep.Start(adapter.StartStatePostStart); err != nil {
		t.Fatalf("Start endpoint: %v", err)
	}
	waitEndpointReady(t, ep)

	socksPort := startEndpointH2ConnectStreamSocksRouter(t, ep)
	conn := TM.IntegrationSocksTCPDial(t, socksPort, targetPort)
	if err := conn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}

	type result struct {
		n   int64
		err error
	}
	done := make(chan result, 1)
	go func() {
		n, _, err := TM.IntegrationMeasureTCPDownloadWriteToMbps(conn, 2*time.Second)
		done <- result{n: n, err: err}
	}()

	select {
	case r := <-done:
		if r.err != nil && r.n < 8 {
			t.Fatalf("WriteTo-only iperf banner: %v (n=%d)", r.err, r.n)
		}
		if r.n < 8 {
			t.Fatalf("WriteTo-only got %d bytes want >= 8 (iperf3 banner)", r.n)
		}
		t.Logf("endpoint H2 WriteTo-only iperf banner: %d bytes", r.n)
	case <-time.After(9 * time.Second):
		t.Fatal("WriteTo-only download blocked >9s (docker hang shape)")
	}
}
