package relay

import (
	"io"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type mockProxyCloser struct {
	closed atomic.Bool
	unblock chan struct{}
}

func (m *mockProxyCloser) Close() error {
	m.closed.Store(true)
	if m.unblock != nil {
		close(m.unblock)
	}
	return nil
}

// TestProxyCloseClosersMapRace stress-concurrent Close vs register/delete on closers (R4).
func TestProxyCloseClosersMapRace(t *testing.T) {
	const workers = 48
	for round := 0; round < 8; round++ {
		p := &Proxy{}
		var wg sync.WaitGroup
		wg.Add(workers)
		for i := 0; i < workers; i++ {
			go func() {
				defer wg.Done()
				c := &mockProxyCloser{unblock: make(chan struct{})}
				p.mx.Lock()
				if !p.closed {
					if p.closers == nil {
						p.closers = make(map[io.Closer]struct{})
					}
					p.closers[c] = struct{}{}
					p.refCount.Add(1)
				}
				p.mx.Unlock()
				select {
				case <-c.unblock:
				case <-time.After(200 * time.Millisecond):
				}
				p.mx.Lock()
				if p.closers != nil {
					delete(p.closers, c)
				}
				p.mx.Unlock()
				p.refCount.Done()
			}()
		}
		time.Sleep(time.Millisecond)
		if err := p.Close(); err != nil {
			t.Fatalf("round %d Close: %v", round, err)
		}
		wg.Wait()
	}
}

// TestProxyCloseWaitsForSessionUnregister verifies Close waits refCount before clearing closers.
func TestProxyCloseWaitsForSessionUnregister(t *testing.T) {
	p := &Proxy{}
	entry := &mockProxyCloser{unblock: make(chan struct{})}
	p.mx.Lock()
	p.closers = map[io.Closer]struct{}{entry: {}}
	p.refCount.Add(1)
	p.mx.Unlock()

	unregistered := make(chan struct{})
	go func() {
		<-entry.unblock
		p.mx.Lock()
		if p.closers != nil {
			delete(p.closers, entry)
		}
		p.mx.Unlock()
		p.refCount.Done()
		close(unregistered)
	}()

	if err := p.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-unregistered:
	case <-time.After(2 * time.Second):
		t.Fatal("session did not unregister before Close returned")
	}
	p.mx.Lock()
	if p.closers != nil {
		t.Fatal("closers map should be nil after Close")
	}
	p.mx.Unlock()
}
