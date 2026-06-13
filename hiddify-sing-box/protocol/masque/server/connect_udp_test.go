package server

import (
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	qmasque "github.com/quic-go/masque-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/sagernet/sing-box/option"
	TM "github.com/sagernet/sing-box/transport/masque"
	"github.com/yosida95/uritemplate/v3"
)

func TestExtendedMasqueTunnelProtocol(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		req  *http.Request
		want string
	}{
		{
			name: "h2 protocol header",
			req:  &http.Request{Header: http.Header{":protocol": []string{"connect-udp"}}},
			want: "connect-udp",
		},
		{
			name: "h3 proto field",
			req:  &http.Request{Proto: "connect-udp"},
			want: "connect-udp",
		},
		{
			name: "http version ignored",
			req:  &http.Request{Proto: "HTTP/2.0"},
			want: "",
		},
		{
			name: "nil request",
			req:  nil,
			want: "",
		},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := ExtendedMasqueTunnelProtocol(tc.req); got != tc.want {
				t.Fatalf("got %q want %q", got, tc.want)
			}
		})
	}
}

func TestConnectUDPResolveDialToHTTPStatus(t *testing.T) {
	t.Parallel()
	if got := ConnectUDPResolveDialToHTTPStatus(nil); got != http.StatusOK {
		t.Fatalf("nil err: got %d want %d", got, http.StatusOK)
	}
	if got := ConnectUDPResolveDialToHTTPStatus(&net.DNSError{IsTimeout: true}); got != http.StatusGatewayTimeout {
		t.Fatalf("dns timeout: got %d want %d", got, http.StatusGatewayTimeout)
	}
	if got := ConnectUDPResolveDialToHTTPStatus(&net.DNSError{IsNotFound: true}); got != http.StatusBadGateway {
		t.Fatalf("dns not found: got %d want %d", got, http.StatusBadGateway)
	}
	if got := ConnectUDPResolveDialToHTTPStatus(&net.AddrError{}); got != http.StatusBadRequest {
		t.Fatalf("addr error: got %d want %d", got, http.StatusBadRequest)
	}
	if got := ConnectUDPResolveDialToHTTPStatus(&net.ParseError{}); got != http.StatusBadRequest {
		t.Fatalf("parse error: got %d want %d", got, http.StatusBadRequest)
	}
	if got := ConnectUDPResolveDialToHTTPStatus(net.ErrClosed); got != http.StatusInternalServerError {
		t.Fatalf("generic error: got %d want %d", got, http.StatusInternalServerError)
	}
}

func TestHandleConnectUDPRejectsWrongH2Protocol(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodConnect, "/masque/udp/example.com/443", nil)
	req.Header.Set(":protocol", "connect-ip")
	parsed := &qmasque.Request{Host: "example.com", Target: "example.com:443"}

	HandleConnectUDP(rec, req, parsed, &qmasque.Proxy{}, ConnectUDPTargetPolicy{})

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status: got %d want %d", rec.Code, http.StatusBadRequest)
	}
}

func TestHandleConnectUDPRejectsInvalidTarget(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodConnect, "/masque/udp/example.invalid/443", nil)
	req.Header.Set(":protocol", "connect-udp")
	// Pass target policy; H2 ResolveUDPAddr fails with DNS → 502 + Proxy-Status.
	parsed := &qmasque.Request{Host: "example.invalid", Target: "example.invalid:443"}

	HandleConnectUDP(rec, req, parsed, &qmasque.Proxy{}, ConnectUDPTargetPolicy{AllowPrivateTargets: true})

	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status: got %d want %d", rec.Code, http.StatusBadGateway)
	}
	if got := rec.Header().Get("Proxy-Status"); got == "" {
		t.Fatal("expected Proxy-Status header on resolve failure")
	}
}

func TestHandleConnectUDPRejectsPrivateTargetH2(t *testing.T) {
	t.Parallel()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodConnect, "/masque/udp/127.0.0.1/53", nil)
	req.Header.Set(":protocol", "connect-udp")
	parsed := &qmasque.Request{Host: "127.0.0.1", Target: "127.0.0.1:53"}

	HandleConnectUDP(rec, req, parsed, &qmasque.Proxy{}, ConnectUDPTargetPolicy{})

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status: got %d want %d", rec.Code, http.StatusForbidden)
	}
}

func TestHandleConnectUDPRejectsBlockedPortH2(t *testing.T) {
	t.Parallel()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodConnect, "/masque/udp/example.com/53", nil)
	req.Header.Set(":protocol", "connect-udp")
	parsed := &qmasque.Request{Host: "example.com", Target: "example.com:53"}

	HandleConnectUDP(rec, req, parsed, &qmasque.Proxy{}, ConnectUDPTargetPolicy{
		BlockedTargetPorts: []uint16{53},
	})

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status: got %d want %d", rec.Code, http.StatusForbidden)
	}
}

type mockH3ConnectUDPResponse struct {
	httptest.ResponseRecorder
}

func (m *mockH3ConnectUDPResponse) HTTPStream() *http3.Stream {
	return nil
}

func TestHandleConnectUDPRejectsPrivateTargetH3(t *testing.T) {
	t.Parallel()
	rec := &mockH3ConnectUDPResponse{}
	req := httptest.NewRequest(http.MethodConnect, "/masque/udp/127.0.0.1/53", nil)
	parsed := &qmasque.Request{Host: "127.0.0.1", Target: "127.0.0.1:53"}

	HandleConnectUDP(rec, req, parsed, &qmasque.Proxy{}, ConnectUDPTargetPolicy{})

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status: got %d want %d", rec.Code, http.StatusForbidden)
	}
}

func TestHandleConnectUDPH2SetsCapsuleProtocolHeader(t *testing.T) {
	uc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer uc.Close()
	port := uc.LocalAddr().(*net.UDPAddr).Port
	target := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodConnect, "/masque/udp/127.0.0.1/"+strconv.Itoa(port), io.NopCloser(http.NoBody))
	req.Header.Set(":protocol", "connect-udp")
	parsed := &qmasque.Request{Host: "127.0.0.1", Target: target}

	done := make(chan struct{})
	go func() {
		HandleConnectUDP(rec, req, parsed, &qmasque.Proxy{}, ConnectUDPTargetPolicy{AllowPrivateTargets: true})
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("handler did not return")
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("status: got %d want %d", rec.Code, http.StatusOK)
	}
	want := TM.CapsuleProtocolHeaderValueH2()
	if got := rec.Header().Get(http3.CapsuleProtocolHeader); got != want {
		t.Fatalf("Capsule-Protocol: got %q want %q", got, want)
	}
}

func TestBuildMuxHandlerConnectUDPAuthDenied(t *testing.T) {
	t.Setenv("MASQUE_SERVER_CONNECT_STREAM_ONLY", "0")
	const udpTemplate = "https://127.0.0.1:443/masque/udp/{target_host}/{target_port}"
	handler, err := BuildMuxHandler(MuxHost{
		Options: option.MasqueEndpointOptions{AllowPrivateTargets: true},
		Authorize: func(*http.Request) bool {
			return false
		},
		ResolveTemplates: func(option.MasqueEndpointOptions) (string, string, string) {
			return udpTemplate, "https://127.0.0.1:443/masque/ip/{ip_version}/{ipproto}/{target_host}/{target_port}", "https://127.0.0.1:443/masque/tcp/{target_host}/{target_port}"
		},
		RelaxAuthority: func(option.MasqueEndpointOptions, string) bool { return false },
		RequestForParse: func(r *http.Request, _ *uritemplate.Template, _ bool) *http.Request {
			return r
		},
		AuthorityMatches: func(_, _ string, _ bool) bool { return true },
	}, option.MasqueTCPRelayTemplate)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodConnect, "/masque/udp/example.com/443", nil)
	req.Host = "127.0.0.1:443"
	req.URL.Scheme = "https"
	req.Header.Set(":protocol", "connect-udp")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status: got %d want %d", rec.Code, http.StatusUnauthorized)
	}
}
