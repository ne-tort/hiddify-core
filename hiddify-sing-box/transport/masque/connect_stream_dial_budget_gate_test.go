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
	const hold = 80
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
		t.Fatal("81st dial must fail when stream budget saturated")
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
