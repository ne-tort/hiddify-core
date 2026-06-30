package conn

import (
	"context"
	"io"
	"sync/atomic"
	"testing"
	"time"

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
		ctx0UDPPayload([]byte("b")),
	}
	c := NewH3Conn(str, masqueAddr{"l"}, masqueAddr{"r"})
	defer func() { _ = c.Close() }()

	buf := make([]byte, 8)
	n, _, err := c.ReadFrom(buf)
	if err != nil {
		t.Fatalf("read a: %v", err)
	}
	if got := string(buf[:n]); got != "a" {
		t.Fatalf("read a: got %q", got)
	}
	str.try = [][]byte{
		ctx0UDPPayload([]byte("c")),
	}
	for _, w := range []string{"b", "c"} {
		n, _, err := c.ReadFrom(buf)
		if err != nil {
			t.Fatalf("read %s: %v", w, err)
		}
		if got := string(buf[:n]); got != w {
			t.Fatalf("read %s: got %q", w, got)
		}
	}
	if got := str.recvCalls.Load(); got != 2 {
		t.Fatalf("blocking ReceiveDatagram calls=%d want 2 (c from prefetch drain after b)", got)
	}
}

// TestH3ConnS2CPrefetchPumpStagesTryReceive verifies background pump fills prefetch without blocking recv.
func TestH3ConnS2CPrefetchPumpStagesTryReceive(t *testing.T) {
	t.Parallel()
	str := &backlogH3Stream{blockRecv: make(chan struct{})}
	str.try = [][]byte{
		ctx0UDPPayload([]byte("pump")),
	}
	c := NewH3Conn(str, masqueAddr{"l"}, masqueAddr{"r"})
	defer func() { _ = c.Close() }()

	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		if str.recvCalls.Load() > 0 {
			break
		}
		time.Sleep(time.Millisecond)
	}
	buf := make([]byte, 8)
	n, _, err := c.ReadFrom(buf)
	if err != nil {
		t.Fatalf("ReadFrom: %v", err)
	}
	if got := string(buf[:n]); got != "pump" {
		t.Fatalf("got %q want pump", got)
	}
	if got := str.recvCalls.Load(); got != 0 {
		t.Fatalf("blocking ReceiveDatagram calls=%d want 0 (prefetch pump served read)", got)
	}
}
