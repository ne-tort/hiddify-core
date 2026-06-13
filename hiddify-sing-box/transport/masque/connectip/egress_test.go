package connectip

import (
	"context"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"
)

type taggedWriteSession struct {
	tag     byte
	writes  atomic.Int32
	written atomic.Int32
}

func (s *taggedWriteSession) ReadPacket(_ []byte) (int, error) {
	return 0, net.ErrClosed
}

func (s *taggedWriteSession) WritePacket(payload []byte) ([]byte, error) {
	if len(payload) == 0 {
		return nil, context.DeadlineExceeded
	}
	s.writes.Add(1)
	if payload[0] != s.tag {
		return nil, context.DeadlineExceeded
	}
	s.written.Add(1)
	return nil, nil
}

func (s *taggedWriteSession) Close() error { return nil }

func TestConnectIPOutboundWriterInterleavesRetryablePackets(t *testing.T) {
	sess := &taggedWriteSession{tag: 'B'}
	stack, err := NewNetstack(context.Background(), sess, NetstackOptions{
		LocalIPv4: netip.MustParseAddr("198.18.0.2"),
		LocalIPv6: netip.MustParseAddr("fd00::2"),
	})
	if err != nil {
		t.Fatalf("create stack: %v", err)
	}
	defer stack.Close()
	stack.ensureOutboundWriter()

	payloadA := borrowOutboundBuf(4)
	copy(payloadA, []byte{'A', 0x00, 0x00, 0x28})
	payloadB := borrowOutboundBuf(4)
	copy(payloadB, []byte{'B', 0x00, 0x00, 0x28})

	stack.noteOutboundEnqueued()
	stack.noteOutboundEnqueued()
	stack.outboundCh <- outboundItem{payload: payloadA, persist: 0}
	stack.outboundCh <- outboundItem{payload: payloadB, persist: 0}

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if sess.written.Load() == 1 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if got := sess.written.Load(); got != 1 {
		t.Fatalf("expected packet B written before A retries exhaust, got written=%d writes=%d", got, sess.writes.Load())
	}
	if got := sess.writes.Load(); got < 2 {
		t.Fatalf("expected at least one retry on packet A before B succeeded, got writes=%d", got)
	}
}

func TestConnectIPOutboundQueueMetricsTracksDepth(t *testing.T) {
	var metrics OutboundQueueMetrics
	stack, err := NewNetstack(context.Background(), &taggedWriteSession{tag: 'X'}, NetstackOptions{
		LocalIPv4:            netip.MustParseAddr("198.18.0.2"),
		LocalIPv6:            netip.MustParseAddr("fd00::2"),
		OutboundQueueMetrics: &metrics,
	})
	if err != nil {
		t.Fatalf("create stack: %v", err)
	}
	defer stack.Close()
	stack.ensureOutboundWriter()

	payload := borrowOutboundBuf(4)
	copy(payload, []byte{'X', 0x00, 0x00, 0x28})
	if !stack.enqueueOutboundPayload(payload, 0) {
		t.Fatal("expected enqueue")
	}
	if got := metrics.Depth.Load(); got != 1 {
		t.Fatalf("depth=%d want 1", got)
	}
	if got := metrics.DepthHigh.Load(); got != 1 {
		t.Fatalf("depthHigh=%d want 1", got)
	}
}

func TestOutboundWriterSchedulesDrainAfterWrite(t *testing.T) {
	stack, err := NewNetstack(context.Background(), &taggedWriteSession{tag: 'X'}, NetstackOptions{
		LocalIPv4: netip.MustParseAddr("198.18.0.2"),
		LocalIPv6: netip.MustParseAddr("fd00::2"),
	})
	if err != nil {
		t.Fatalf("create stack: %v", err)
	}
	defer stack.Close()
	stack.ensureOutboundWriter()
	payload := borrowOutboundBuf(4)
	copy(payload, []byte{'X', 0x00, 0x00, 0x28})
	if _, err := stack.deliverOutboundWriterItem(payload, 0); err != nil {
		t.Fatalf("deliver: %v", err)
	}
	select {
	case <-stack.outboundPoke:
	case <-time.After(time.Second):
		t.Fatal("expected drain poke after successful WritePacket")
	}
}

func TestScheduleOutboundDrainAfterWritePokesDrain(t *testing.T) {
	stack, err := NewNetstack(context.Background(), &taggedWriteSession{tag: 'X'}, NetstackOptions{
		LocalIPv4: netip.MustParseAddr("198.18.0.2"),
		LocalIPv6: netip.MustParseAddr("fd00::2"),
	})
	if err != nil {
		t.Fatalf("create stack: %v", err)
	}
	defer stack.Close()
	stack.ensureOutboundWriter()
	select {
	case <-stack.outboundPoke:
		t.Fatal("poke channel should start empty")
	default:
	}
	stack.scheduleOutboundDrainAfterWrite()
	select {
	case <-stack.outboundPoke:
	case <-time.After(time.Second):
		t.Fatal("expected poke after scheduleOutboundDrainAfterWrite")
	}
}

func TestNetstackOnOutboundQueuedOnDrain(t *testing.T) {
	var queued atomic.Int32
	sess := &packetPipeSession{
		recvCh:  make(chan []byte, 8),
		sendCh:  make(chan []byte, 8),
		closeCh: make(chan struct{}),
	}
	stack, err := NewNetstack(context.Background(), sess, NetstackOptions{
		LocalIPv4: netip.MustParseAddr("198.18.0.2"),
		LocalIPv6: netip.MustParseAddr("fd00::2"),
		OnOutboundQueued: func() {
			queued.Add(1)
		},
	})
	if err != nil {
		t.Fatalf("create stack: %v", err)
	}
	defer stack.Close()

	pkt := buildTestIPv4TCP(t, 0x18, []byte("payload"))
	stack.InjectInboundOwned(CloneInboundFrame(pkt))
	stack.ScheduleOutboundDrain()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if queued.Load() > 0 {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("OnOutboundQueued not called (queued=%d)", queued.Load())
}
