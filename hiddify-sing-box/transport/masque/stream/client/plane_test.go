package client

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"

	M "github.com/sagernet/sing/common/metadata"
)

type stubHopHost struct {
	attempts int
}

func (h *stubHopHost) DialAttempt(ctx context.Context, destination M.Socksaddr) (net.Conn, error) {
	h.attempts++
	if h.attempts == 1 {
		return nil, errors.New("retry")
	}
	client, server := net.Pipe()
	_ = server.Close()
	return client, nil
}

func (h *stubHopHost) TryHTTPFallbackSwitch(err error) bool             { return false }
func (h *stubHopHost) HTTPLayerAutoEnabled() bool                 { return false }
func (h *stubHopHost) IsAuthFailure(err error) bool                   { return false }
func (h *stubHopHost) ClearHTTPFallbackAfterGiveUp()                  {}
func (h *stubHopHost) RebuildOverlayTransport()                       {}
func (h *stubHopHost) PreAdvanceHop()                                 {}
func (h *stubHopHost) AdvanceHopLocked() (advanced bool, resetErr error) { return true, nil }

func TestPlaneDialTCPStreamUsesHopChain(t *testing.T) {
	host := &stubHopHost{}
	p := Plane{Host: host}
	conn, err := p.DialTCPStream(context.Background(), M.Socksaddr{Addr: netip.AddrFrom4([4]byte{127, 0, 0, 1}), Port: 9})
	if err != nil {
		t.Fatalf("DialTCPStream: %v", err)
	}
	_ = conn.Close()
	if host.attempts < 2 {
		t.Fatalf("expected hop retry, attempts=%d", host.attempts)
	}
}
