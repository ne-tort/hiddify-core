package conn

import (
	"sync/atomic"
	"testing"
	"time"
)

type fakeBacklogSender struct {
	backlog atomic.Int32
	sends   atomic.Int32
}

func (f *fakeBacklogSender) SendDatagram([]byte) error {
	f.sends.Add(1)
	f.backlog.Add(1)
	return nil
}

func (f *fakeBacklogSender) DatagramSendBacklog() int {
	return int(f.backlog.Load())
}

func TestH3C2SWriterBlocksUntilSoftBacklogRoom(t *testing.T) {
	f := &fakeBacklogSender{}
	f.backlog.Store(int32(h3C2SSendBacklogSoftLimit + 8))
	w := newH3C2SWriter(f, 0)

	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = w.writeBytes(nil, nil, []byte("x"))
	}()

	select {
	case <-done:
		t.Fatal("writeBytes returned while backlog >= soft limit")
	case <-time.After(20 * time.Millisecond):
	}

	f.backlog.Store(int32(h3C2SSendBacklogSoftLimit - 1))
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("writeBytes did not resume after backlog fell below soft limit")
	}
	if f.sends.Load() != 1 {
		t.Fatalf("sends=%d want 1", f.sends.Load())
	}
}
