package connectip

import (
	"context"
	"errors"
	"testing"

	cip "github.com/quic-go/connect-ip-go"
)

type dialHopFakeHost struct {
	attempts          []bool
	overlayH2         bool
	fallbackOnAttempt map[int]bool
	errOnAttempt      map[int]error
	resetH3           int
	resetH2           int
}

func (h *dialHopFakeHost) DialAttempt(_ context.Context, useHTTP2 bool) (*cip.Conn, error) {
	idx := len(h.attempts)
	h.attempts = append(h.attempts, useHTTP2)
	if err, ok := h.errOnAttempt[idx]; ok {
		return nil, err
	}
	return &cip.Conn{}, nil
}

func (h *dialHopFakeHost) TryHTTPFallbackSwitch(err error) bool {
	if err == nil {
		return false
	}
	idx := len(h.attempts) - 1
	if h.fallbackOnAttempt == nil {
		return false
	}
	if pivot, ok := h.fallbackOnAttempt[idx]; ok && pivot {
		h.overlayH2 = !h.overlayH2
		return true
	}
	return false
}

func (h *dialHopFakeHost) CurrentOverlayH2() bool {
	return h.overlayH2
}

func (h *dialHopFakeHost) ResetIPH3Transport() {
	h.resetH3++
}

func (h *dialHopFakeHost) ResetH2UDPTransport() {
	h.resetH2++
}

func TestDialOnCurrentHopSuccessFirstAttempt(t *testing.T) {
	host := &dialHopFakeHost{}
	conn, err := DialOnCurrentHop(context.Background(), host, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if conn == nil {
		t.Fatal("expected conn")
	}
	if len(host.attempts) != 1 || host.attempts[0] {
		t.Fatalf("attempts=%v want [false]", host.attempts)
	}
	if host.resetH3 != 0 || host.resetH2 != 0 {
		t.Fatalf("unexpected churn resetH3=%d resetH2=%d", host.resetH3, host.resetH2)
	}
}

func TestDialOnCurrentHopHTTPFallbackPivot(t *testing.T) {
	host := &dialHopFakeHost{
		fallbackOnAttempt: map[int]bool{0: true},
		errOnAttempt:      map[int]error{0: errors.New("h3 down")},
	}
	conn, err := DialOnCurrentHop(context.Background(), host, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if conn == nil {
		t.Fatal("expected conn")
	}
	if len(host.attempts) != 2 || host.attempts[0] || !host.attempts[1] {
		t.Fatalf("attempts=%v want [false true]", host.attempts)
	}
	if host.resetH3 != 0 || host.resetH2 != 0 {
		t.Fatalf("fallback pivot should not churn transports: resetH3=%d resetH2=%d", host.resetH3, host.resetH2)
	}
}

func TestDialOnCurrentHopH3ChurnThenSuccess(t *testing.T) {
	host := &dialHopFakeHost{
		errOnAttempt: map[int]error{0: errors.New("h3 stale")},
	}
	conn, err := DialOnCurrentHop(context.Background(), host, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if conn == nil {
		t.Fatal("expected conn")
	}
	if len(host.attempts) != 2 || host.attempts[0] || host.attempts[1] {
		t.Fatalf("attempts=%v want [false false]", host.attempts)
	}
	if host.resetH3 != 1 {
		t.Fatalf("resetH3=%d want 1", host.resetH3)
	}
}

func TestDialOnCurrentHopH2ChurnThenSuccess(t *testing.T) {
	host := &dialHopFakeHost{
		errOnAttempt: map[int]error{0: errors.New("h2 stale")},
	}
	conn, err := DialOnCurrentHop(context.Background(), host, true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if conn == nil {
		t.Fatal("expected conn")
	}
	if len(host.attempts) != 2 || !host.attempts[0] || !host.attempts[1] {
		t.Fatalf("attempts=%v want [true true]", host.attempts)
	}
	if host.resetH2 != 1 {
		t.Fatalf("resetH2=%d want 1", host.resetH2)
	}
}

func TestDialOnCurrentHopPropagatesFinalError(t *testing.T) {
	dialErr := errors.New("dial failed")
	host := &dialHopFakeHost{
		errOnAttempt: map[int]error{0: dialErr, 1: dialErr},
	}
	conn, err := DialOnCurrentHop(context.Background(), host, false)
	if conn != nil {
		t.Fatal("expected nil conn")
	}
	if !errors.Is(err, dialErr) {
		t.Fatalf("err=%v want %v", err, dialErr)
	}
	if host.resetH3 != 1 {
		t.Fatalf("resetH3=%d want 1", host.resetH3)
	}
}
