package stream

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestGATEJoinConnectStreamPhaseVisibleInErrorChain(t *testing.T) {
	t.Parallel()
	err := JoinConnectStreamPhase("quic warm", context.DeadlineExceeded)
	if err == nil {
		t.Fatal("nil err")
	}
	msg := err.Error()
	if !strings.Contains(msg, "quic warm") {
		t.Fatalf("phase label missing: %q", msg)
	}
	if !errors.Is(err, Errs.TCPConnectStreamFailed) {
		t.Fatalf("expected TCPConnectStreamFailed in chain: %v", err)
	}
}
