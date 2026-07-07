package masque_test

// GATE-DIAL-BUDGET: parallel CONNECT-stream dials must not fail when sing-box passes
// an already-canceled parent ctx (field symptom: @30.0s context canceled pile-up).

import (
	"context"
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
