package server

import (
	"errors"
	"testing"
)

func TestTCPBindFailureRetryable(t *testing.T) {
	t.Parallel()
	win := errors.New("listen tcp 127.0.0.1:65058: bind: An attempt was made to access a socket in a way forbidden by its access permissions.")
	if !TCPBindFailureRetryable(win) {
		t.Fatalf("expected Windows-style bind denial to be retryable")
	}
	if TCPBindFailureRetryable(errors.New("address already in use")) {
		t.Fatalf("conflict error must not be classified as ephemeral-port retry")
	}
}

func TestEphemeralDualBindTCPRetryable(t *testing.T) {
	t.Parallel()
	winInUse := errors.New("listen tcp 127.0.0.1:59940: bind: Only one usage of each socket address (protocol/network address/port) is normally permitted.")
	if !EphemeralDualBindTCPRetryable(winInUse) {
		t.Fatalf("expected Windows TCP EADDRINUSE on ephemeral dual-bind to be retryable")
	}
	if !EphemeralDualBindTCPRetryable(errors.New("address already in use")) {
		t.Fatal("expected address already in use to be retryable for ephemeral dual-bind")
	}
	if EphemeralDualBindTCPRetryable(errors.New("connection refused")) {
		t.Fatal("unexpected errors must not trigger ephemeral dual-bind retry")
	}
}
