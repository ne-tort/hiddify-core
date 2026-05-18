package masque

import (
	"io"
	"sync"
	"testing"
	"time"
)

func TestConnectStreamUploadBridgeDecouplesWriter(t *testing.T) {
	pr, pw := io.Pipe()
	bridge := newConnectStreamUploadBridge(pw)
	t.Cleanup(func() { _ = bridge.Close(); _ = pr.Close() })

	payload := make([]byte, 16*1024)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		time.Sleep(50 * time.Millisecond)
		buf := make([]byte, len(payload))
		_, _ = io.ReadFull(pr, buf)
	}()
	if _, err := bridge.Write(payload); err != nil {
		t.Fatalf("write before pipe read: %v", err)
	}
	wg.Wait()
}
