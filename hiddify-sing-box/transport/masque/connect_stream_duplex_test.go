package masque

import (
	"sync"
	"testing"
	"time"
)

func TestConnectStreamDuplexGateReserveAndUpload(t *testing.T) {
	g := &connectStreamDuplexGate{
		enabled:     true,
		windowBytes: 64 * 1024,
		uploadChunk: 4096,
		ringCap:     3 * 64 * 1024,
	}
	g.cond.L = &g.mu
	g.active.Store(1)

	g.CommitResponse(32 * 1024)
	g.CommitResponse(32 * 1024)

	done := make(chan struct{})
	go func() {
		g.WaitResponseSlot(8 * 1024)
		close(done)
	}()

	select {
	case <-done:
		t.Fatal("expected third wait to block")
	case <-time.After(50 * time.Millisecond):
	}

	g.RecordUpload(40 * 1024)
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("wait did not unblock after upload credit")
	}

	if inflight := g.inflightLocked(); inflight > int64(g.windowBytes) {
		t.Fatalf("inflight %d > window %d", inflight, g.windowBytes)
	}
}

func TestConnectStreamDuplexGateInactiveNoBlock(t *testing.T) {
	g := newConnectStreamDuplexGate()
	g.enabled = true
	for i := 0; i < 100; i++ {
		g.WaitResponseSlot(1024)
	}
	if g.inflightLocked() != 0 {
		t.Fatalf("inactive gate should not charge responseAhead, got inflight %d", g.inflightLocked())
	}
}

func TestConnectStreamDuplexGateMaxChunks(t *testing.T) {
	g := &connectStreamDuplexGate{enabled: true, windowBytes: 64 * 1024, uploadChunk: 4096}
	g.active.Store(1)
	if g.MaxDownloadChunk() != 64*1024 {
		t.Fatalf("download chunk %d", g.MaxDownloadChunk())
	}
	if g.MaxUploadChunk(8*1024*1024) != 4096 {
		t.Fatalf("upload chunk %d", g.MaxUploadChunk(8*1024*1024))
	}
	g.active.Store(0)
	if g.MaxDownloadChunk() != connectStreamDownloadSinkMaxBulk {
		t.Fatalf("bulk download chunk %d", g.MaxDownloadChunk())
	}
}

func TestConnectStreamDuplexGateInflightUntilUploadCredit(t *testing.T) {
	g := &connectStreamDuplexGate{
		enabled:     true,
		windowBytes: 64 * 1024,
		uploadChunk: 4096,
	}
	g.cond.L = &g.mu
	g.active.Store(1)

	g.CommitResponse(48 * 1024)
	g.CommitResponse(32 * 1024)
	if g.inflightLocked() != 80*1024 {
		t.Fatalf("inflight %d", g.inflightLocked())
	}
	g.RecordUpload(20 * 1024)
	if g.inflightLocked() != 60*1024 {
		t.Fatalf("after partial upload credit inflight %d", g.inflightLocked())
	}
}

func TestConnectStreamDuplexGateConcurrentUploadUnblocks(t *testing.T) {
	g := &connectStreamDuplexGate{
		enabled:     true,
		windowBytes: 16 * 1024,
		uploadChunk: 1024,
	}
	g.cond.L = &g.mu
	g.active.Store(1)

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		g.WaitResponseSlot(12 * 1024)
		g.CommitResponse(12 * 1024)
	}()
	time.Sleep(20 * time.Millisecond)
	g.RecordUpload(12 * 1024)
	wg.Wait()
}
