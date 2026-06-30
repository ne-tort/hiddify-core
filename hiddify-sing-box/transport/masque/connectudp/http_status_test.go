package connectudp

import (
	"net"
	"net/http"
	"testing"
)

func TestResolveDialToHTTPStatus(t *testing.T) {
	t.Parallel()
	if got := ResolveDialToHTTPStatus(nil); got != http.StatusOK {
		t.Fatalf("nil: got %d want %d", got, http.StatusOK)
	}
	if got := ResolveDialToHTTPStatus(&net.DNSError{IsTimeout: true}); got != http.StatusGatewayTimeout {
		t.Fatalf("dns timeout: got %d", got)
	}
	if got := ResolveDialToHTTPStatus(&net.DNSError{IsNotFound: true}); got != http.StatusBadGateway {
		t.Fatalf("dns not found: got %d", got)
	}
	if got := ResolveDialToHTTPStatus(&net.AddrError{}); got != http.StatusBadRequest {
		t.Fatalf("addr: got %d", got)
	}
	if got := ResolveDialToHTTPStatus(net.ErrClosed); got != http.StatusInternalServerError {
		t.Fatalf("closed: got %d", got)
	}
}
