package server

import (
	"errors"
	"net"
	"testing"
)

func TestShutdownMasqueEndpointNilStackIsSafe(t *testing.T) {
	t.Parallel()
	if err := ShutdownMasqueEndpoint(ShutdownMasqueEndpointConfig{}); err != nil {
		t.Fatalf("nil shutdown: %v", err)
	}
}

func TestShutdownMasqueEndpointIdempotentAfterPartialClose(t *testing.T) {
	t.Parallel()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	stack := &MasqueStack{PacketConn: pc}
	if err := ShutdownMasqueEndpoint(ShutdownMasqueEndpointConfig{Stack: stack}); err != nil {
		t.Fatalf("first shutdown: %v", err)
	}
	if err := ShutdownMasqueEndpoint(ShutdownMasqueEndpointConfig{Stack: stack}); err != nil {
		t.Fatalf("second shutdown: %v", err)
	}
}

func TestExpectedShutdownErrorCoversNetClosed(t *testing.T) {
	t.Parallel()
	if !ExpectedShutdownError(net.ErrClosed) {
		t.Fatal("net.ErrClosed should be expected shutdown")
	}
	if ExpectedShutdownError(errors.New("dial tcp: connection refused")) {
		t.Fatal("unexpected error must not classify as shutdown")
	}
}
