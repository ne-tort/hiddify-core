package server

import (
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	qmasque "github.com/quic-go/masque-go"
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

	HandleConnectUDP(rec, req, parsed, &qmasque.Proxy{})

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status: got %d want %d", rec.Code, http.StatusBadRequest)
	}
}

func TestHandleConnectUDPRejectsInvalidTarget(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodConnect, "/masque/udp/bad/0", nil)
	req.Header.Set(":protocol", "connect-udp")
	parsed := &qmasque.Request{Host: "bad", Target: "not-a-udp-target"}

	HandleConnectUDP(rec, req, parsed, &qmasque.Proxy{})

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status: got %d want %d", rec.Code, http.StatusBadRequest)
	}
	if got := rec.Header().Get("Proxy-Status"); got == "" {
		t.Fatal("expected Proxy-Status header on resolve failure")
	}
}
