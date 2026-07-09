package masque_test

// GATE-DIAL: H2O-parity CONNECT-stream dial — handshake ctx boundary only; QUIC MAX_STREAMS backpressure.

import (
	"context"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	M "github.com/sagernet/sing/common/metadata"
)

const (
	dialGateWorkers = 16
	dialGateTotal   = 48
	dialGateMinOK   = 0.95
)

// TestGATEH3ConnectStreamParallelCanceledParentDialSucceeds — DNS cascade may cancel parent
// before CONNECT completes; handshake ctx must still dial (connect-ip-go WithoutCancel).
func TestGATEH3ConnectStreamParallelCanceledParentDialSucceeds(t *testing.T) {
	t.Parallel()
	_, targetPort, session, baseCtx := setupSynthChurnHarness(t)
	dest := M.ParseSocksaddrHostPort("127.0.0.1", targetPort)

	var okCount atomic.Int32
	jobs := make(chan struct{}, dialGateTotal)
	for i := 0; i < dialGateTotal; i++ {
		jobs <- struct{}{}
	}
	close(jobs)

	var wg sync.WaitGroup
	for w := 0; w < dialGateWorkers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range jobs {
				parent, parentCancel := context.WithCancel(baseCtx)
				parentCancel()
				reqCtx, cancel := context.WithTimeout(parent, 2*time.Second)
				conn, err := session.DialContext(reqCtx, "tcp", dest)
				cancel()
				if err != nil {
					continue
				}
				okCount.Add(1)
				_ = conn.Close()
			}
		}()
	}
	wg.Wait()

	okRate := float64(okCount.Load()) / float64(dialGateTotal)
	if okRate < dialGateMinOK {
		t.Fatalf("GATE-DIAL ok rate %.2f want >= %.2f (handshake WithoutCancel regression)", okRate, dialGateMinOK)
	}
}

// TestGATEH3ConnectStreamQUICMaxStreamsBackpressure — H2O parity: when peer bidi budget is
// full, excess dials block in OpenStreamSync until ctx expires; slot recycle on conn Close.
func TestGATEH3ConnectStreamQUICMaxStreamsBackpressure(t *testing.T) {
	t.Parallel()
	_, targetPort, session, baseCtx := setupSynthChurnHarness(t)
	dest := M.ParseSocksaddrHostPort("127.0.0.1", targetPort)
	const maxHold = 120
	held := make([]net.Conn, 0, maxHold)
	defer func() {
		for _, c := range held {
			_ = c.Close()
		}
	}()
	saturated := false
	for i := 0; i < maxHold; i++ {
		reqCtx, cancel := context.WithTimeout(baseCtx, 5*time.Second)
		conn, err := session.DialContext(reqCtx, "tcp", dest)
		cancel()
		if err != nil {
			if len(held) == 0 {
				t.Fatalf("first dial failed: %v", err)
			}
			if strings.Contains(err.Error(), "stream budget") || strings.Contains(err.Error(), "in-flight queue") {
				t.Fatalf("must not use client semaphores (H2O parity), got: %v", err)
			}
			saturated = true
			break
		}
		held = append(held, conn)
	}
	if !saturated {
		t.Fatalf("could not saturate QUIC bidi budget within %d held streams", len(held))
	}
	_ = held[0].Close()
	held = held[1:]
	retryCtx, retryCancel := context.WithTimeout(baseCtx, 8*time.Second)
	conn, retryErr := session.DialContext(retryCtx, "tcp", dest)
	retryCancel()
	if retryErr != nil {
		t.Fatalf("dial after stream Close recycles QUIC slot: %v", retryErr)
	}
	_ = conn.Close()
	for _, c := range held {
		_ = c.Close()
	}
	held = held[:0]
}

const (
	browserGateWorkers      = 16
	browserGateTotal        = 64
	browserGateMinOK        = 0.95
	browserParentDialBudget = 30 * time.Second
)

// TestGATEH3ConnectStreamBrowserParallelParent30sDeadline — sing-box :443 sniff budget (~30s).
func TestGATEH3ConnectStreamBrowserParallelParent30sDeadline(t *testing.T) {
	t.Parallel()
	_, targetPort, session, baseCtx := setupSynthChurnHarness(t)
	dest := M.ParseSocksaddrHostPort("127.0.0.1", targetPort)

	var okCount atomic.Int32
	jobs := make(chan struct{}, browserGateTotal)
	for i := 0; i < browserGateTotal; i++ {
		jobs <- struct{}{}
	}
	close(jobs)

	var wg sync.WaitGroup
	for w := 0; w < browserGateWorkers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range jobs {
				parent, parentCancel := context.WithTimeout(baseCtx, browserParentDialBudget)
				conn, err := session.DialContext(parent, "tcp", dest)
				parentCancel()
				if err != nil {
					continue
				}
				okCount.Add(1)
				_ = conn.Close()
			}
		}()
	}
	wg.Wait()

	okRate := float64(okCount.Load()) / float64(browserGateTotal)
	if okRate < browserGateMinOK {
		t.Fatalf("GATE-BROWSER-30S ok rate %.2f want >= %.2f", okRate, browserGateMinOK)
	}
}

// TestGATEH3ConnectStreamBrowserBurstWithHeldStreams — live streams + new :443 dials on one session.
func TestGATEH3ConnectStreamBrowserBurstWithHeldStreams(t *testing.T) {
	t.Parallel()
	_, targetPort, session, baseCtx := setupSynthChurnHarness(t)
	dest := M.ParseSocksaddrHostPort("127.0.0.1", targetPort)
	const hold = 40
	held := make([]net.Conn, 0, hold)
	defer func() {
		for _, c := range held {
			_ = c.Close()
		}
	}()
	for i := 0; i < hold; i++ {
		reqCtx, cancel := context.WithTimeout(baseCtx, 8*time.Second)
		conn, err := session.DialContext(reqCtx, "tcp", dest)
		cancel()
		if err != nil {
			t.Fatalf("hold dial@%d: %v", i, err)
		}
		held = append(held, conn)
	}

	const burst = 8
	var okCount atomic.Int32
	var roundTripPhase atomic.Int32
	jobs := make(chan struct{}, burst)
	for i := 0; i < burst; i++ {
		jobs <- struct{}{}
	}
	close(jobs)
	var wg sync.WaitGroup
	for w := 0; w < burst; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range jobs {
				parent, parentCancel := context.WithTimeout(baseCtx, browserParentDialBudget)
				conn, err := session.DialContext(parent, "tcp", dest)
				parentCancel()
				if err != nil {
					if strings.Contains(err.Error(), "connect roundtrip") {
						roundTripPhase.Add(1)
					}
					continue
				}
				okCount.Add(1)
				_ = conn.Close()
			}
		}()
	}
	wg.Wait()

	if roundTripPhase.Load() > 0 {
		t.Fatalf("GATE-BROWSER-HELD: %d dials failed in connect roundtrip (ghost stream / slot leak)", roundTripPhase.Load())
	}
	if int(okCount.Load()) != burst {
		t.Fatalf("GATE-BROWSER-HELD: ok=%d want %d with %d held streams", okCount.Load(), burst, hold)
	}
}
