package server

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"

	TM "github.com/sagernet/sing-box/transport/masque"
	M "github.com/sagernet/sing/common/metadata"
)

func TestEndpointIsReady(t *testing.T) {
	t.Parallel()
	if EndpointIsReady(nil, false) {
		t.Fatal("expected not ready when ready flag is false")
	}
	if !EndpointIsReady(nil, true) {
		t.Fatal("expected ready when no startup error")
	}
	if EndpointIsReady(net.ErrClosed, true) {
		t.Fatal("expected not ready when startup error is set")
	}
}

func TestDialEndpointTCPRejectsInvalidDestinationAsCapability(t *testing.T) {
	t.Parallel()
	_, err := DialEndpointTCP(context.Background(), net.Dialer{}, nil, "tcp", M.Socksaddr{})
	if err == nil {
		t.Fatal("expected invalid destination to be rejected")
	}
	if !errors.Is(err, TM.ErrCapability) {
		t.Fatalf("expected ErrCapability for invalid destination, got: %v", err)
	}
	if got := TM.ClassifyError(err); got != TM.ErrorClassCapability {
		t.Fatalf("expected capability class for invalid destination, got: %s", got)
	}
}

func TestDialEndpointTCPRejectsUnsupportedNetwork(t *testing.T) {
	t.Parallel()
	_, err := DialEndpointTCP(context.Background(), net.Dialer{}, nil, "udp", M.ParseSocksaddr("127.0.0.1:1"))
	if err == nil {
		t.Fatal("expected unsupported network error")
	}
	if !strings.Contains(err.Error(), "unsupported network") {
		t.Fatalf("expected unsupported network message, got: %v", err)
	}
}

func TestDialEndpointTCPPropagatesStartupError(t *testing.T) {
	t.Parallel()
	startupErr := net.ErrClosed
	_, err := DialEndpointTCP(context.Background(), net.Dialer{}, startupErr, "tcp", M.ParseSocksaddr("127.0.0.1:1"))
	if !errors.Is(err, startupErr) {
		t.Fatalf("expected startup error cause, got: %v", err)
	}
}

func TestListenEndpointPacketPropagatesStartupError(t *testing.T) {
	t.Parallel()
	startupErr := net.ErrClosed
	_, err := ListenEndpointPacket(startupErr)
	if !errors.Is(err, startupErr) {
		t.Fatalf("expected startup error cause, got: %v", err)
	}
}
