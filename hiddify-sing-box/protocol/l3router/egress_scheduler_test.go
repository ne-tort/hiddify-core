package l3routerendpoint

import (
	"context"
	"testing"
	"time"

	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/buf"
)

func newSchedulerTestEndpoint(t *testing.T, opts option.L3RouterEndpointOptions) *Endpoint {
	t.Helper()
	loggerFactory := log.NewNOPFactory()
	ep, err := NewEndpoint(context.Background(), nil, loggerFactory.Logger(), "scheduler-test", opts)
	if err != nil {
		t.Fatalf("NewEndpoint: %v", err)
	}
	return ep.(*Endpoint)
}

func TestEgressSchedulerFairnessNoSessionStarvation(t *testing.T) {
	ep := newSchedulerTestEndpoint(t, option.L3RouterEndpointOptions{
		EgressQueueCapPerSession: 16,
		EgressGlobalQueueBudget:  64,
		EgressBatchSize:          4,
	})
	defer ep.Close()

	for i := 0; i < 8; i++ {
		pa := buf.As([]byte{0x45, 0x00, byte(i)})
		pb := buf.As([]byte{0x45, 0x01, byte(i)})
		qa, _, _ := ep.scheduler.enqueue("owner-a", pa, overflowPolicyDropNew)
		qb, _, _ := ep.scheduler.enqueue("owner-b", pb, overflowPolicyDropNew)
		if !qa || !qb {
			t.Fatalf("enqueue failed at i=%d", i)
		}
	}

	var gotA, gotB int
	for i := 0; i < 6; i++ {
		work, ok := ep.scheduler.nextWork()
		if !ok {
			break
		}
		if work.session == "owner-a" {
			gotA++
		}
		if work.session == "owner-b" {
			gotB++
		}
		for _, env := range work.items {
			if env != nil && env.payload != nil {
				env.payload.Release()
			}
		}
		ep.scheduler.onWorkerDone(work.session)
	}
	if gotA == 0 || gotB == 0 {
		t.Fatalf("expected both sessions to be served, gotA=%d gotB=%d", gotA, gotB)
	}
}

func TestEgressSchedulerBoundedQueue(t *testing.T) {
	ep := newSchedulerTestEndpoint(t, option.L3RouterEndpointOptions{
		EgressQueueCapPerSession: 4,
		EgressGlobalQueueBudget:  6,
		OverflowPolicy:           "drop_new",
	})
	defer ep.Close()

	for i := 0; i < 20; i++ {
		payload := buf.As([]byte{0x45, 0x02, byte(i)})
		queued, _, _ := ep.scheduler.enqueue("owner-a", payload, overflowPolicyDropNew)
		if !queued {
			payload.Release()
		}
	}
	m := ep.SnapshotMetrics()
	if m.QueueDepth > 4 {
		t.Fatalf("queue depth exceeds per-session cap: %d", m.QueueDepth)
	}
	if m.QueueOverflow == 0 {
		t.Fatal("expected queue overflow drops under pressure")
	}
}

func TestEgressSchedulerAQMDropsOnStandingDelay(t *testing.T) {
	ep := newSchedulerTestEndpoint(t, option.L3RouterEndpointOptions{
		EgressQueueCapPerSession: 2,
		EgressGlobalQueueBudget:  2,
		AQMTargetMS:              1,
		AQMIntervalMS:            1,
	})
	defer ep.Close()

	p1 := buf.As([]byte{0x45, 0x03, 0x01})
	q1, _, _ := ep.scheduler.enqueue("owner-a", p1, overflowPolicyDropNew)
	if !q1 {
		t.Fatal("first enqueue failed")
	}
	time.Sleep(2 * time.Millisecond)

	p2 := buf.As([]byte{0x45, 0x03, 0x02})
	q2, _, _ := ep.scheduler.enqueue("owner-a", p2, overflowPolicyDropNew)
	if !q2 {
		t.Fatal("second enqueue failed")
	}
	time.Sleep(2 * time.Millisecond)

	p3 := buf.As([]byte{0x45, 0x03, 0x03})
	q3, _, _ := ep.scheduler.enqueue("owner-a", p3, overflowPolicyDropNew)
	if !q3 {
		p3.Release()
	}
	time.Sleep(2 * time.Millisecond)
	p4 := buf.As([]byte{0x45, 0x03, 0x04})
	q4, _, _ := ep.scheduler.enqueue("owner-a", p4, overflowPolicyDropNew)
	if !q4 {
		p4.Release()
	}

	if ep.SnapshotMetrics().AQMDrops == 0 {
		t.Fatal("expected AQM drop after standing queue delay")
	}
}

func BenchmarkEgressSchedulerEnqueue(b *testing.B) {
	loggerFactory := log.NewNOPFactory()
	epAny, err := NewEndpoint(context.Background(), nil, loggerFactory.Logger(), "bench-scheduler", option.L3RouterEndpointOptions{
		EgressQueueCapPerSession: 2048,
		EgressGlobalQueueBudget:  8192,
		EgressBatchSize:          64,
	})
	if err != nil {
		b.Fatalf("NewEndpoint: %v", err)
	}
	ep := epAny.(*Endpoint)
	defer ep.Close()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		payload := buf.As([]byte{0x45, 0x04, byte(i)})
		queued, _, _ := ep.scheduler.enqueue("owner-a", payload, overflowPolicyDropOldest)
		if !queued {
			payload.Release()
		}
	}
}
