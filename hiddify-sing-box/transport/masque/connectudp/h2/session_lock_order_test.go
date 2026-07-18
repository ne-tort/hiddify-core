package h2

import (
	"net"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

// TestAttachUploadWaitsWithoutSpin covers AUDIT B18 / TASKS F2.4:
// Attach before Register must block on waiter, not 1ms sleep poll.
func TestAttachUploadWaitsWithoutSpin(t *testing.T) {
	reg := NewSessionRegistry()
	key := sessionKey{target: "127.0.0.1:9", mux: "b18-wait"}
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	errCh := make(chan error, 1)
	go func() {
		_, err := reg.AttachUpload(key)
		errCh <- err
	}()

	time.Sleep(50 * time.Millisecond) // Attach is waiting on waiter
	rr := httptest.NewRecorder()
	w := newH2DownlinkWriter(rr, LegProfileDownloadFountain)
	if _, err := reg.RegisterDownload(key, conn, w); err != nil {
		t.Fatal(err)
	}

	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("AttachUpload after Register: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("AttachUpload did not wake on RegisterDownload")
	}
	reg.Release(key) // upload ref
	reg.Release(key) // download ref
}

// TestSessionRegistryLockOrderStress covers AUDIT B9 / TASKS F2.3:
// concurrent Register/Attach/Release must not deadlock (reg.mu → sess.mu).
func TestSessionRegistryLockOrderStress(t *testing.T) {
	reg := NewSessionRegistry()
	var wg sync.WaitGroup
	const n = 32
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			key := sessionKey{target: "127.0.0.1:9", mux: string(rune('a' + i%26))}
			conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
			if err != nil {
				t.Errorf("listen: %v", err)
				return
			}
			defer conn.Close()
			rr := httptest.NewRecorder()
			w := newH2DownlinkWriter(rr, LegProfileDownloadFountain)
			sess, err := reg.RegisterDownload(key, conn, w)
			if err != nil {
				// duplicate mux from parallel — ok
				return
			}
			if _, err := reg.AttachUpload(key); err != nil {
				t.Errorf("attach: %v", err)
			}
			reg.Release(key)
			reg.Release(key)
			_ = sess
		}(i)
	}
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("deadlock: Register/Attach/Release stress exceeded 10s")
	}
}
