package tun

import (
	"context"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

type blockingPacketReader struct {
	block   chan struct{}
	reads   atomic.Int32
	release chan struct{}
}

func newBlockingPacketReader() *blockingPacketReader {
	return &blockingPacketReader{
		block:   make(chan struct{}),
		release: make(chan struct{}),
	}
}

func (r *blockingPacketReader) ReadPacket(ctx context.Context, _ []byte) (int, error) {
	r.reads.Add(1)
	select {
	case <-ctx.Done():
		return 0, ctx.Err()
	case <-r.release:
		return 0, io.EOF
	case <-r.block:
		return 0, io.EOF
	}
}

func (r *blockingPacketReader) unblock() {
	close(r.release)
}

func TestNativeL3PlaneSessionStopRestartIngress(t *testing.T) {
	reader := newBlockingPacketReader()
	bridge := NewL3OverlayBridge(func([]byte) (int, error) { return 0, nil }, &mockL3Writer{}, reader, OverlayNAT{})
	plane := NewNativeL3PlaneSession(bridge)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	plane.StartIngress(ctx)
	if err := plane.WaitReady(ctx); err != nil {
		t.Fatalf("WaitReady: %v", err)
	}
	if plane.IngressGeneration() != 1 {
		t.Fatalf("gen=%d want 1", plane.IngressGeneration())
	}

	writer2 := &mockL3Writer{}
	reader2 := newBlockingPacketReader()
	bridge.RebindPacketPlane(writer2, reader2)

	plane.RestartIngress()
	waitCtx, waitCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer waitCancel()
	if err := plane.WaitReady(waitCtx); err != nil {
		t.Fatalf("WaitReady after restart: %v", err)
	}
	if plane.IngressGeneration() != 2 {
		t.Fatalf("gen=%d want 2 after restart", plane.IngressGeneration())
	}

	reader.unblock()
	plane.StopIngress()
}

func TestNativeL3PlaneSessionWaitReadyTimeout(t *testing.T) {
	plane := NewNativeL3PlaneSession(NewL3OverlayBridge(nil, &mockL3Writer{}, nil, OverlayNAT{}))
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if err := plane.WaitReady(ctx); err == nil {
		t.Fatal("expected timeout waiting for ingress without StartIngress")
	}
}

func TestNativeL3PlaneSessionReadFatalHook(t *testing.T) {
	reader := &fatalPacketReader{err: net.ErrClosed}
	bridge := NewL3OverlayBridge(func([]byte) (int, error) { return 0, nil }, &mockL3Writer{}, reader, OverlayNAT{})
	plane := NewNativeL3PlaneSession(bridge)

	var fatal atomic.Bool
	plane.SetReadFatalHook(func(error) { fatal.Store(true) })

	ctx, cancel := context.WithCancel(context.Background())
	plane.StartIngress(ctx)
	deadline := time.Now().Add(2 * time.Second)
	for !fatal.Load() && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	plane.StopIngress()
	if !fatal.Load() {
		t.Fatal("expected read fatal hook")
	}
}

type fatalPacketReader struct {
	err error
}

func (r *fatalPacketReader) ReadPacket(context.Context, []byte) (int, error) {
	return 0, r.err
}
