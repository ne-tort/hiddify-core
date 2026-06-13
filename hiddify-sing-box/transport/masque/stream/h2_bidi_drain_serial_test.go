package stream

import (
	"io"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// blockingDownloadInner blocks in Read until released; detects concurrent Read calls.
type blockingDownloadInner struct {
	release chan struct{}
	active  int32
	overlap atomic.Bool
}

func (d *blockingDownloadInner) Read(p []byte) (int, error) {
	if atomic.AddInt32(&d.active, 1) > 1 {
		d.overlap.Store(true)
	}
	defer atomic.AddInt32(&d.active, -1)
	select {
	case <-d.release:
		return 0, io.EOF
	case <-time.After(150 * time.Millisecond):
		return 0, nil
	}
}

func (d *blockingDownloadInner) Close() error { return nil }

// TestDownloadPathAdapterSerializesConcurrentRead (A8-2): production downloadPathAdapter must
// serialize drain vs Read vs WriteTo on one H2 CONNECT response body.
func TestDownloadPathAdapterSerializesConcurrentRead(t *testing.T) {
	inner := &blockingDownloadInner{release: make(chan struct{})}
	adapter := &downloadPathAdapter{inner: inner}

	var wg sync.WaitGroup
	wg.Add(2)
	for i := 0; i < 2; i++ {
		go func() {
			defer wg.Done()
			buf := make([]byte, 8)
			_, _ = adapter.Read(buf)
		}()
	}

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		close(inner.release)
		<-done
	}

	if inner.overlap.Load() {
		t.Fatal("downloadPathAdapter allowed concurrent Read on H2 response body")
	}
}
