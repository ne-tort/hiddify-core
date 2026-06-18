package masque

// H3 bisect: masque.Endpoint + CM.Runtime + SOCKS iperf -R WriteTo (docker sing-box client shape).

import (
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
	TM "github.com/sagernet/sing-box/transport/masque"
	strm "github.com/sagernet/sing-box/transport/masque/stream"
	"github.com/sagernet/sing/service"
	"github.com/yosida95/uritemplate/v3"

	_ "github.com/sagernet/sing-box/internal/http2xconnect"
)

func startEndpointH3ConnectStreamLaunchStack(t *testing.T) int {
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
	if stack == nil || stack.H3Server == nil || stack.PacketConn == nil {
		t.Fatal("expected HTTP/3 listener on LaunchMasqueStack")
	}
	t.Cleanup(func() {
		if shutErr := server.ShutdownMasqueEndpoint(server.ShutdownMasqueEndpointConfig{Stack: stack}); shutErr != nil {
			t.Errorf("shutdown LaunchMasqueStack: %v", shutErr)
		}
	})

	udpAddr, ok := stack.PacketConn.LocalAddr().(*net.UDPAddr)
	if !ok || udpAddr == nil {
		t.Fatalf("unexpected UDP listener addr: %T", stack.PacketConn.LocalAddr())
	}
	port := udpAddr.Port
	rawTpl := fmt.Sprintf("https://127.0.0.1:%d/masque/tcp/{target_host}/{target_port}", port)
	tcpTemplate, err = uritemplate.New(rawTpl)
	if err != nil {
		t.Fatalf("tcp template: %v", err)
	}
	time.Sleep(30 * time.Millisecond)
	return port
}

func startEndpointH3ConnectStream(t *testing.T, ctx context.Context, proxyPort int) *Endpoint {
	t.Helper()
	epRaw, err := NewEndpoint(ctx, nil, log.StdLogger(), "masque-h3", option.MasqueEndpointOptions{
		ServerOptions: option.ServerOptions{Server: "127.0.0.1", ServerPort: uint16(proxyPort)},
		HopPolicy:     option.MasqueHopPolicySingle,
		TransportMode: option.MasqueTransportModeConnectUDP,
		TCPTransport:  option.MasqueTCPTransportConnectStream,
		HTTPLayer:     option.MasqueHTTPLayerH3,
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
	return ep
}

func benchEndpointH3IperfReverseWriteToMbps(t *testing.T, ep *Endpoint) float64 {
	t.Helper()
	const benchDur = 2 * time.Second
	targetPort := TM.IntegrationStartH2FakeIperfStreamingDownloadTarget(t)
	socksPort := startEndpointH2ConnectStreamSocksRouter(t, ep)
	conn := TM.IntegrationSocksTCPDial(t, socksPort, targetPort)
	if err := conn.SetDeadline(time.Now().Add(benchDur + 8*time.Second)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}
	banner := make([]byte, 8)
	if _, err := io.ReadFull(conn, banner); err != nil {
		t.Fatalf("read iperf banner: %v", err)
	}
	if string(banner) != "iperf3\r\n" {
		t.Fatalf("banner: got %q", string(banner))
	}
	if _, err := conn.Write([]byte("FAKEIPERF")); err != nil {
		t.Fatalf("write fake iperf params: %v", err)
	}
	n, mbps, err := TM.IntegrationMeasureTCPDownloadWriteToMbps(conn, benchDur)
	if err != nil && n == 0 {
		t.Fatalf("iperf reverse WriteTo: %v", err)
	}
	return mbps
}

// TestEndpointConnectStreamH3IperfReverseWriteToMbps (H3-C) — masque.Endpoint + CM.Runtime iperf -R WriteTo.
func TestEndpointConnectStreamH3IperfReverseWriteToMbps(t *testing.T) {
	minMbps := TM.ExportConnectStreamSynthProdMinMbps
	proxyPort := startEndpointH3ConnectStreamLaunchStack(t)
	ep := startEndpointH3ConnectStream(t, context.Background(), proxyPort)
	mbps := benchEndpointH3IperfReverseWriteToMbps(t, ep)
	t.Logf("endpoint H3 iperf reverse WriteTo: %.1f Mbit/s", mbps)
	if mbps < minMbps {
		t.Fatalf("endpoint H3 iperf reverse %.1f < %.0f Mbit/s (AGENTS KPI)", mbps, minMbps)
	}
}

// TestGATEEndpointH3SingBoxNetworkManagerIperfReverseWriteToMbps — sing-box client ctx; KPI ≥1000 Mbit/s.
func TestGATEEndpointH3SingBoxNetworkManagerIperfReverseWriteToMbps(t *testing.T) {
	minMbps := TM.ExportConnectStreamSynthProdMinMbps
	direct := &testMasqueDirectOutbound{
		Adapter: outbound.NewAdapter(C.TypeDirect, "direct", []string{"tcp", "udp"}, nil),
	}
	ctx := service.ContextWith[adapter.OutboundManager](
		context.Background(),
		testMasqueOutboundManager{outbounds: []adapter.Outbound{direct}},
	)
	ctx = service.ContextWith[adapter.NetworkManager](
		ctx,
		testMasqueNetworkManager{autoDetect: false},
	)
	proxyPort := startEndpointH3ConnectStreamLaunchStack(t)
	ep := startEndpointH3ConnectStream(t, ctx, proxyPort)
	mbps := benchEndpointH3IperfReverseWriteToMbps(t, ep)
	t.Logf("endpoint H3 sing-box ctx iperf reverse WriteTo: %.1f Mbit/s", mbps)
	if mbps < minMbps {
		t.Fatalf("endpoint H3 sing-box ctx %.1f < %.0f Mbit/s (AGENTS KPI)", mbps, minMbps)
	}
}
