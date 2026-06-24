package conn

import (
	"context"
	_ "embed"
	"strings"
	"testing"
	"time"
)

//go:embed h3.go
var h3GoSource string

type duplexH3Stream struct {
	asyncH3NoWakeStream
	recv chan []byte
}

func (s *duplexH3Stream) ReceiveDatagram(ctx context.Context) ([]byte, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case b := <-s.recv:
		return b, nil
	}
}

// TestH3ConnReadFromEntryFlushGuard locks CL3: ReadFrom must flush pending C2S before blocking recv (H2 parity).
func TestH3ConnReadFromEntryFlushGuard(t *testing.T) {
	t.Parallel()
	if !strings.Contains(h3GoSource, "c.write.flushPendingWriteBatch()") {
		t.Fatal("CL3: ReadFrom must call flushPendingWriteBatch before blocking ReceiveDatagram")
	}
}

// TestH3ConnReadFromFlushesPendingC2SBatch verifies duplex ReadFrom after partial NoWake C2S batch.
func TestH3ConnReadFromFlushesPendingC2SBatch(t *testing.T) {
	t.Parallel()
	str := &duplexH3Stream{recv: make(chan []byte, 1)}
	c := NewH3Conn(str, masqueAddr{"l"}, masqueAddr{"r"})
	defer func() { _ = c.Close() }()

	payload := make([]byte, 64)
	if _, err := c.WriteTo(payload, nil); err != nil {
		t.Fatal(err)
	}
	before := str.flushes.Load()
	str.recv <- ctx0UDPPayload([]byte("x"))
	buf := make([]byte, 8)
	if _, _, err := c.ReadFrom(buf); err != nil {
		t.Fatal(err)
	}
	time.Sleep(5 * time.Millisecond)
	if got := str.flushes.Load(); got < before {
		t.Fatalf("flushes=%d regressed from %d after duplex ReadFrom", got, before)
	}
	if got := str.noWake.Load(); got != 1 {
		t.Fatalf("NoWake sends=%d want 1", got)
	}
}
