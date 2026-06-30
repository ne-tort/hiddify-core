package conn

import (
	"io"
	"os"
	"sync/atomic"
	"testing"
	"time"
)

type stallH2ResponseBody struct {
	release chan struct{}
	active  atomic.Int32
}

func (s *stallH2ResponseBody) Read(p []byte) (int, error) {
	s.active.Add(1)
	defer s.active.Add(-1)
	<-s.release
	if len(p) == 0 {
		return 0, nil
	}
	p[0] = 'x'
	return 1, io.EOF
}

func (s *stallH2ResponseBody) Close() error { return nil }

// TestH2ConnectStreamResponseBodyAwaitReadNoGoroutinePileup (STR-4a6) deadline pokes must not
// stack concurrent underlying reads on the same response body.
func TestH2ConnectStreamResponseBodyAwaitReadNoGoroutinePileup(t *testing.T) {
	t.Parallel()
	stall := &stallH2ResponseBody{release: make(chan struct{})}
	body := NewH2ConnectStreamResponseBody(stall).(*h2ConnectStreamResponseBody)
	buf := make([]byte, 1)

	body.SetReadDeadline(time.Now().Add(5 * time.Millisecond))
	if _, err := body.Read(buf); err != os.ErrDeadlineExceeded {
		t.Fatalf("first Read: %v want ErrDeadlineExceeded", err)
	}
	if got := stall.active.Load(); got != 1 {
		t.Fatalf("after first deadline Read active=%d want 1 (underlying read still draining)", got)
	}

	done := make(chan struct{})
	go func() {
		body.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
		_, _ = body.Read(buf)
		close(done)
	}()

	deadline := time.Now().Add(20 * time.Millisecond)
	for time.Now().Before(deadline) {
		if stall.active.Load() > 1 {
			t.Fatalf("second Read started before first drained: active=%d", stall.active.Load())
		}
		time.Sleep(time.Millisecond)
	}

	close(stall.release)
	<-done
	if stall.active.Load() != 0 {
		t.Fatalf("active=%d want 0 after drain", stall.active.Load())
	}
}
