package masque_test

// GATE-DIAL-BUDGET: parallel CONNECT-stream dials must not fail when sing-box passes
// an already-canceled parent ctx (field symptom: @30.0s context canceled pile-up).

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
	dialBudgetGateWorkers = 16
	dialBudgetGateTotal   = 48
	dialBudgetGateMinOK   = 0.95
)

// TestGATEH3ConnectStreamParallelCanceledParentDialSucceeds localizes the field failure mode
// where many TUN dials share one H3 session and parent ctx cancels before CONNECT completes.
func TestGATEH3ConnectStreamParallelCanceledParentDialSucceeds(t *testing.T) {
	t.Parallel()
	_, targetPort, session, baseCtx := setupSynthChurnHarness(t)
	dest := M.ParseSocksaddrHostPort("127.0.0.1", targetPort)

	var okCount atomic.Int32
	jobs := make(chan struct{}, dialBudgetGateTotal)
	for i := 0; i < dialBudgetGateTotal; i++ {
		jobs <- struct{}{}
	}
	close(jobs)

	var wg sync.WaitGroup
	for w := 0; w < dialBudgetGateWorkers; w++ {
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

	okRate := float64(okCount.Load()) / float64(dialBudgetGateTotal)
	if okRate < dialBudgetGateMinOK {
		t.Fatalf("GATE-DIAL-BUDGET ok rate %.2f want >= %.2f (handshake boundary / warm regression)", okRate, dialBudgetGateMinOK)
	}
}

// TestGATEH3ConnectStreamBudgetSaturatedQueuesNotRoundTrip localizes field burst failure:
// when peer bidi budget is full, excess dials queue with phase "stream budget" instead of
// blocking inside http3 OpenStreamSync until "connect roundtrip: context canceled".
func TestGATEH3ConnectStreamBudgetSaturatedQueuesNotRoundTrip(t *testing.T) {
	t.Parallel()
	_, targetPort, session, baseCtx := setupSynthChurnHarness(t)
	dest := M.ParseSocksaddrHostPort("127.0.0.1", targetPort)
	const hold = 48
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
	shortCtx, shortCancel := context.WithTimeout(baseCtx, 500*time.Millisecond)
	_, err := session.DialContext(shortCtx, "tcp", dest)
	shortCancel()
	if err == nil {
		t.Fatal("49th dial must fail when stream budget saturated")
	}
	if !strings.Contains(err.Error(), "stream budget") {
		t.Fatalf("want stream budget phase, got: %v", err)
	}
	_ = held[0].Close()
	held = held[1:]
	retryCtx, retryCancel := context.WithTimeout(baseCtx, 8*time.Second)
	conn, retryErr := session.DialContext(retryCtx, "tcp", dest)
	retryCancel()
	if retryErr != nil {
		t.Fatalf("dial after slot release: %v", retryErr)
	}
	_ = conn.Close()
}

const (
	browserGateWorkers     = 16
	browserGateTotal       = 64
	browserGateMinOK       = 0.95
	browserParentDialBudget = 30 * time.Second
)

// TestGATEH3ConnectStreamBrowserParallelParent30sDeadline localizes field browser/TUN
// dials where sing-box passes a ~30s parent ctx per TCP flow (:443 TLS sniff budget).
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
		t.Fatalf("GATE-BROWSER-30S ok rate %.2f want >= %.2f (queue deadline / roundtrip pile-up)", okRate, browserGateMinOK)
	}
}

// TestGATEH3ConnectStreamBrowserBurstWithHeldStreams localizes browser tab load: many
// live CONNECT streams plus new :443 dials on one H3 session (must not hang in queue).
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

	const burst = 8 // 48 budget − 40 held = 8 free slots
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
		t.Fatalf("GATE-BROWSER-HELD: %d dials failed in connect roundtrip (queue/budget regression)", roundTripPhase.Load())
	}
	if int(okCount.Load()) != burst {
		t.Fatalf("GATE-BROWSER-HELD: ok=%d want %d with %d held streams", okCount.Load(), burst, hold)
	}
}
