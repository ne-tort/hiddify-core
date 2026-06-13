package masque

import (
	"github.com/sagernet/sing-box/transport/masque/session"
	"context"
	"errors"
	"net"
	"testing"

	strm "github.com/sagernet/sing-box/transport/masque/stream"
	M "github.com/sagernet/sing/common/metadata"
)

type dialHopChainFake struct {
	attempts          int
	errOnAttempt      map[int]error
	fallbackOnAttempt map[int]bool
	rebuilds          int
	advanceCalls      int
	advanceOK         bool
	resetErr          error
	preAdvance        func()
	authOnAttempt     map[int]bool
	httpFallback      bool
}

func (h *dialHopChainFake) DialAttempt(_ context.Context, _ M.Socksaddr) (net.Conn, error) {
	idx := h.attempts
	h.attempts++
	if err, ok := h.errOnAttempt[idx]; ok {
		return nil, err
	}
	return &net.TCPConn{}, nil
}

func (h *dialHopChainFake) TryHTTPFallbackSwitch(err error) bool {
	if err == nil {
		return false
	}
	idx := h.attempts - 1
	if h.fallbackOnAttempt == nil {
		return false
	}
	return h.fallbackOnAttempt[idx]
}

func (h *dialHopChainFake) HTTPLayerFallbackEnabled() bool {
	return h.httpFallback
}

func (h *dialHopChainFake) IsAuthFailure(err error) bool {
	if err == nil {
		return false
	}
	idx := h.attempts - 1
	if h.authOnAttempt == nil {
		return false
	}
	return h.authOnAttempt[idx]
}

func (h *dialHopChainFake) ClearHTTPFallbackAfterGiveUp() {}

func (h *dialHopChainFake) RebuildOverlayTransport() {
	h.rebuilds++
}

func (h *dialHopChainFake) PreAdvanceHop() {
	if h.preAdvance != nil {
		h.preAdvance()
	}
}

func (h *dialHopChainFake) AdvanceHopLocked() (bool, error) {
	h.advanceCalls++
	if h.advanceOK {
		return true, h.resetErr
	}
	return false, h.resetErr
}

func TestDialWithHopChainSuccessFirstAttempt(t *testing.T) {
	host := &dialHopChainFake{}
	conn, err := strm.DialWithHopChain(context.Background(), host, M.ParseSocksaddrHostPort("example.com", 443))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if conn == nil {
		t.Fatal("expected conn")
	}
	if host.attempts != 1 || host.advanceCalls != 0 {
		t.Fatalf("attempts=%d advanceCalls=%d", host.attempts, host.advanceCalls)
	}
}

func TestDialWithHopChainHTTPFallbackPivot(t *testing.T) {
	host := &dialHopChainFake{
		fallbackOnAttempt: map[int]bool{0: true},
		errOnAttempt:      map[int]error{0: errors.New("h3 down")},
	}
	conn, err := strm.DialWithHopChain(context.Background(), host, M.ParseSocksaddrHostPort("example.com", 443))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if conn == nil {
		t.Fatal("expected conn")
	}
	if host.attempts != 2 {
		t.Fatalf("attempts=%d want 2", host.attempts)
	}
}

func TestDialWithHopChainAdvancesHopAfterRetryableFailure(t *testing.T) {
	host := &dialHopChainFake{
		errOnAttempt: map[int]error{0: errors.New("timeout")},
		advanceOK:    true,
	}
	conn, err := strm.DialWithHopChain(context.Background(), host, M.ParseSocksaddrHostPort("example.com", 443))
	if err != nil {
		t.Fatalf("unexpected error after hop advance redial: %v", err)
	}
	if conn == nil {
		t.Fatal("expected conn after hop advance")
	}
	if host.advanceCalls != 1 {
		t.Fatalf("advanceCalls=%d want 1", host.advanceCalls)
	}
	if host.attempts != 2 {
		t.Fatalf("expected redial after hop advance, attempts=%d", host.attempts)
	}
}

func TestDialWithHopChainCapabilityErrorDoesNotAdvanceHop(t *testing.T) {
	host := &dialHopChainFake{
		errOnAttempt: map[int]error{0: strm.Errs.Capability},
		advanceOK:    true,
	}
	_, err := strm.DialWithHopChain(context.Background(), host, M.Socksaddr{})
	if !errors.Is(err, strm.Errs.Capability) {
		t.Fatalf("expected capability error, got %v", err)
	}
	if host.advanceCalls != 0 {
		t.Fatalf("advanceCalls=%d want 0 on capability error", host.advanceCalls)
	}
}

func TestDialWithHopChainAuthFailureStopsWithoutAdvance(t *testing.T) {
	authErr := errors.New("auth denied")
	host := &dialHopChainFake{
		errOnAttempt:  map[int]error{0: authErr},
		authOnAttempt: map[int]bool{0: true},
		advanceOK:     true,
	}
	_, err := strm.DialWithHopChain(context.Background(), host, M.ParseSocksaddrHostPort("example.com", 443))
	if !errors.Is(err, authErr) {
		t.Fatalf("expected auth error, got %v", err)
	}
	if host.advanceCalls != 0 {
		t.Fatalf("advanceCalls=%d want 0 on auth failure", host.advanceCalls)
	}
}

func TestDialWithHopChainOverlayChurnWhenFallbackEnabled(t *testing.T) {
	host := &dialHopChainFake{
		httpFallback: true,
		errOnAttempt: map[int]error{
			0: errors.New("stale transport"),
			1: errors.New("still stale"),
			2: errors.New("hop exhausted"),
		},
		advanceOK: false,
	}
	_, err := strm.DialWithHopChain(context.Background(), host, M.ParseSocksaddrHostPort("example.com", 443))
	if err == nil {
		t.Fatal("expected error")
	}
	if host.rebuilds != 1 {
		t.Fatalf("rebuilds=%d want 1 overlay churn before hop advance", host.rebuilds)
	}
}

func TestConnectStreamChosenLogFields(t *testing.T) {
	target, dial := strm.ConnectStreamChosenLogFields(strm.ConnectStreamLogInput{
		TCPURLHost: "proxy.example:443",
		ResolveDialAddr: func() string {
			return "198.51.100.1:443"
		},
	})
	if target != "proxy.example:443" || dial != "198.51.100.1:443" {
		t.Fatalf("got target=%q dial=%q", target, dial)
	}
}

func TestStreamIsConnectStreamHTTP400(t *testing.T) {
	if !strm.IsConnectStreamHTTP400(errors.Join(session.ErrTCPConnectStreamFailed, errors.New("status=400 url=x"))) {
		t.Fatal("expected HTTP 400 detection")
	}
	if strm.IsConnectStreamHTTP400(session.ErrCapability) {
		t.Fatal("capability error must not match HTTP 400")
	}
}
