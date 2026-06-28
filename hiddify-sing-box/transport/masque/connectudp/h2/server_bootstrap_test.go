package h2

import (
	"net"
	"net/http"
	"sync"
	"testing"
)

func TestRegisterDownloadBeforeOKRejectsDuplicate(t *testing.T) {
	reg := NewSessionRegistry()
	target := "127.0.0.1:9"
	mux := "dup-key"
	conn1, err := net.DialUDP("udp", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = conn1.Close() }()
	conn2, err := net.DialUDP("udp", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9})
	if err != nil {
		t.Fatalf("dial2: %v", err)
	}
	defer func() { _ = conn2.Close() }()

	r1, _ := http.NewRequest(http.MethodConnect, "https://example/masque/udp/h/p", nil)
	r1.Header.Set(MasqueUDPStreamRoleHeader, StreamRoleDownload)
	r1.Header.Set(MasqueUDPMuxKeyHeader, mux)
	w1 := noopResponseWriter{}
	if err := RegisterDownloadBeforeOK(w1, r1, conn1, target, reg); err != nil {
		t.Fatalf("first register: %v", err)
	}

	r2, _ := http.NewRequest(http.MethodConnect, "https://example/masque/udp/h/p", nil)
	r2.Header.Set(MasqueUDPStreamRoleHeader, StreamRoleDownload)
	r2.Header.Set(MasqueUDPMuxKeyHeader, mux)
	w2 := noopResponseWriter{}
	if err := RegisterDownloadBeforeOK(w2, r2, conn2, target, reg); !IsDuplicateDownloadSession(err) {
		t.Fatalf("second register: %v want duplicate", err)
	}
	reg.Release(sessionKey{mux: mux, target: target})
}

func TestRegisterDownloadBeforeOKConcurrentDuplicate(t *testing.T) {
	reg := NewSessionRegistry()
	target := "127.0.0.1:9"
	mux := "race-key"
	var wg sync.WaitGroup
	var okCount int
	var dupCount int
	var mu sync.Mutex
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			conn, err := net.DialUDP("udp", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9})
			if err != nil {
				t.Errorf("dial: %v", err)
				return
			}
			defer func() { _ = conn.Close() }()
			r, _ := http.NewRequest(http.MethodConnect, "https://example/masque/udp/h/p", nil)
			r.Header.Set(MasqueUDPStreamRoleHeader, StreamRoleDownload)
			r.Header.Set(MasqueUDPMuxKeyHeader, mux)
			err = RegisterDownloadBeforeOK(noopResponseWriter{}, r, conn, target, reg)
			mu.Lock()
			switch {
			case err == nil:
				okCount++
			case IsDuplicateDownloadSession(err):
				dupCount++
			default:
				t.Errorf("register: %v", err)
			}
			mu.Unlock()
		}()
	}
	wg.Wait()
	if okCount != 1 {
		t.Fatalf("exactly one register ok: got %d", okCount)
	}
	if dupCount != 7 {
		t.Fatalf("seven duplicates: got %d", dupCount)
	}
	reg.Release(sessionKey{mux: mux, target: target})
}
