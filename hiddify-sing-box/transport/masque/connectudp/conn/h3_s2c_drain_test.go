package conn

import (
	"context"
	"io"
	"sync/atomic"
	"testing"

	"github.com/quic-go/quic-go"
)

type backlogH3Stream struct {
	block     [][]byte
	try       [][]byte
	recvCalls atomic.Int64
	blockRecv chan struct{}
}

func (s *backlogH3Stream) Read([]byte) (int, error)  { return 0, io.EOF }
func (s *backlogH3Stream) Write([]byte) (int, error) { return 0, nil }
func (s *backlogH3Stream) Close() error              { return nil }
func (s *backlogH3Stream) CancelRead(quic.StreamErrorCode) {}
func (s *backlogH3Stream) SendDatagram([]byte) error { return nil }

func (s *backlogH3Stream) ReceiveDatagram(ctx context.Context) ([]byte, error) {
	s.recvCalls.Add(1)
	if len(s.block) > 0 {
		b := s.block[0]
		s.block = s.block[1:]
		return b, nil
	}
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-s.blockRecv:
		return nil, ctx.Err()
	}
}

func (s *backlogH3Stream) TryReceiveDatagram() ([]byte, bool) {
	if len(s.try) == 0 {
		return nil, false
	}
	b := s.try[0]
	s.try = s.try[1:]
	return b, true
}

func ctx0UDPPayload(payload []byte) []byte {
	raw := quic.AcquireMasqueDatagramRecvBuf(1 + len(payload))
	raw[0] = 0
	copy(raw[1:], payload)
	return raw[:1+len(payload)]
}

// TestH3ConnReadFromDrainsTryReceiveBacklog verifies CL1: after blocking recv, TryReceive backlog is prefetched.
func TestH3ConnReadFromDrainsTryReceiveBacklog(t *testing.T) {
	t.Parallel()
	str := &backlogH3Stream{blockRecv: make(chan struct{})}
	str.block = [][]byte{
		ctx0UDPPayload([]byte("a")),
	}
	str.try = [][]byte{
		ctx0UDPPayload([]byte("b")),
		ctx0UDPPayload([]byte("c")),
	}
	c := NewH3Conn(str, masqueAddr{"l"}, masqueAddr{"r"})
	defer func() { _ = c.Close() }()

	buf := make([]byte, 8)
	want := []string{"a", "b", "c"}
	for i, w := range want {
		n, _, err := c.ReadFrom(buf)
		if err != nil {
			t.Fatalf("read %d: %v", i, err)
		}
		if got := string(buf[:n]); got != w {
			t.Fatalf("read %d: got %q want %q", i, got, w)
		}
	}
	if got := str.recvCalls.Load(); got != 1 {
		t.Fatalf("blocking ReceiveDatagram calls=%d want 1 (b/c from prefetch drain)", got)
	}
}
