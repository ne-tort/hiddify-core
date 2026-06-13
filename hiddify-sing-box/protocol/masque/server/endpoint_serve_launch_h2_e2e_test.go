package server

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"testing"
	"time"

	"github.com/quic-go/quic-go/http3"
	"github.com/sagernet/sing-box/option"
	cip "github.com/sagernet/sing-box/transport/masque/connectip"
	"github.com/yosida95/uritemplate/v3"

	_ "github.com/sagernet/sing-box/internal/http2xconnect"
)

// TestLaunchMasqueStackH2ExtendedConnectIPSmoke verifies HTTP/2 collateral from LaunchMasqueStack
// serves CONNECT-IP Extended CONNECT end-to-end (docker connect-ip-h2 hybrid path).
func TestLaunchMasqueStackH2ExtendedConnectIPSmoke(t *testing.T) {
	t.Parallel()

	host := ConnectIPHandlerHost{
		Tag:     "launch-h2-smoke",
		Type:    "masque",
		Options: option.MasqueEndpointOptions{AllowPrivateTargets: true},
		RequestForParse: func(r *http.Request, _ *uritemplate.Template, _ bool) *http.Request {
			return r
		},
		RelaxAuthority: func(option.MasqueEndpointOptions, string) bool { return true },
	}

	var ipTemplate *uritemplate.Template
	mux := http.NewServeMux()
	mux.HandleFunc("/masque/ip", func(w http.ResponseWriter, r *http.Request) {
		_ = http.NewResponseController(w).EnableFullDuplex()
		HandleConnectIPRequest(host, w, r, ipTemplate)
	})

	h3TLS := connectIPHandlerH2TestTLS.Clone()
	h3TLS.NextProtos = []string{http3.NextProtoH3}
	collateralTLS := connectIPHandlerH2TestTLS.Clone()

	stack, err := LaunchMasqueStack(LaunchMasqueStackConfig{
		Handler:         mux,
		ListenHost:      "127.0.0.1",
		ListenPort:      0,
		HTTP3TLS:        h3TLS,
		CollateralTLS:   collateralTLS,
		ValidateUDP:     func(net.PacketConn) error { return nil },
	})
	if err != nil {
		t.Fatalf("LaunchMasqueStack: %v", err)
	}
	if stack == nil || stack.HTTP2Server == nil || stack.TCPTLSListener == nil {
		t.Fatal("expected HTTP/2 collateral listener on full stack")
	}
	t.Cleanup(func() {
		if shutErr := ShutdownMasqueEndpoint(ShutdownMasqueEndpointConfig{Stack: stack}); shutErr != nil {
			t.Errorf("shutdown: %v", shutErr)
		}
	})

	tcpAddr, ok := stack.TCPTLSListener.Addr().(*net.TCPAddr)
	if !ok || tcpAddr == nil {
		t.Fatalf("unexpected TCP listener addr: %T", stack.TCPTLSListener.Addr())
	}
	port := tcpAddr.Port
	rawTpl := fmt.Sprintf("https://127.0.0.1:%d/masque/ip", port)
	ipTemplate, err = uritemplate.New(rawTpl)
	if err != nil {
		t.Fatalf("template: %v", err)
	}

	time.Sleep(20 * time.Millisecond)

	clientConn := dialConnectIPHandlerH2Client(t, ipTemplate, port)
	prefixes := waitConnectIPAssignedPrefixes(t, clientConn)
	local4 := prefixes[0].Addr()
	pktSess := cip.NewClientPacketSession(cip.ClientPacketSessionConfig{
		Conn:      clientConn,
		OverlayH2: true,
	})

	probe := makeIPv4UDPPacket(
		local4,
		netip.MustParseAddr("10.0.0.1"),
		43000,
		53,
		[]byte("launch-stack-h2"),
	)
	if _, err := clientConn.WritePacket(probe); err != nil {
		t.Fatalf("WritePacket: %v", err)
	}

	readCtx, readCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer readCancel()
	readBuf := make([]byte, 2048)
	_, readErr := pktSess.ReadPacketWithContext(readCtx, readBuf)
	if readErr != nil && !errors.Is(readErr, context.DeadlineExceeded) && !errors.Is(readErr, context.Canceled) {
		var netErr net.Error
		if !(errors.As(readErr, &netErr) && netErr.Timeout()) {
			t.Fatalf("ReadPacket after WritePacket: %v", readErr)
		}
	}
	_ = readCtx
}
