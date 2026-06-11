package masque

import (
	"context"
	"io"
	"sync"
	"testing"
	"time"
)

func TestConnectStreamDownloadFeederDuplexInflightBounded(t *testing.T) {
	const window = 64 * 1024
	gate := &connectStreamDuplexGate{
		enabled:     true,
		windowBytes: window,
		uploadChunk: 4096,
		ringCap:     3 * window,
	}
	gate.cond.L = &gate.mu
	gate.active.Store(1)

	pr, pw := io.Pipe()
	f := &connectStreamDownloadFeeder{}
	f.start(context.Background(), pr, gate)

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		chunk := make([]byte, 32*1024)
		for i := 0; i < 32; i++ {
			if _, err := pw.Write(chunk); err != nil {
				return
			}
		}
	}()

	time.Sleep(50 * time.Millisecond)
	gate.mu.Lock()
	inflight := gate.inflightLocked()
	gate.mu.Unlock()
	if inflight <= 0 {
		t.Fatalf("feeder should charge responseAhead under duplex gate, inflight=%d", inflight)
	}
	if inflight > int64(window) {
		t.Fatalf("inflight %d exceeds window %d", inflight, window)
	}

	gate.RecordUpload(window)
	time.Sleep(20 * time.Millisecond)
	_ = pw.Close()
	wg.Wait()
}
