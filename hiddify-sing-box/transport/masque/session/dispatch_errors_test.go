package session

import (
	"context"
	"errors"
	"net"
	"testing"
)

func TestUnsupportedNetworkError(t *testing.T) {
	err := UnsupportedNetworkError("udp")
	if !errors.Is(err, DispatchErrs.UnsupportedNetwork) {
		t.Fatalf("expected unsupported network sentinel, got: %v", err)
	}
	if err.Error() == "" {
		t.Fatal("expected non-empty error message")
	}
}

func TestTCPMasqueDirectFallbackEligible(t *testing.T) {
	ctx := context.Background()
	if TCPMasqueDirectFallbackEligible(nil, ctx) {
		t.Fatal("nil error must not be eligible")
	}
	cancelCtx, cancel := context.WithCancel(ctx)
	cancel()
	if TCPMasqueDirectFallbackEligible(DispatchErrs.TCPDial, cancelCtx) {
		t.Fatal("canceled ctx must not be eligible")
	}
	if TCPMasqueDirectFallbackEligible(DispatchErrs.AuthFailed, ctx) {
		t.Fatal("auth failure must not be eligible")
	}
	if TCPMasqueDirectFallbackEligible(DispatchErrs.LifecycleClosed, ctx) {
		t.Fatal("lifecycle closed must not be eligible")
	}
	if TCPMasqueDirectFallbackEligible(net.ErrClosed, ctx) {
		t.Fatal("net.ErrClosed must not be eligible")
	}
	if !TCPMasqueDirectFallbackEligible(DispatchErrs.TCPConnectStreamFailed, ctx) {
		t.Fatal("connect-stream failure must be eligible")
	}
	if !TCPMasqueDirectFallbackEligible(DispatchErrs.TCPDial, ctx) {
		t.Fatal("tcp dial failure must be eligible")
	}
}
