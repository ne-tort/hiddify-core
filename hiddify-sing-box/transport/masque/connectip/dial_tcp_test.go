package connectip

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	M "github.com/sagernet/sing/common/metadata"
)

type dialTCPFakeNetstack struct {
	dial          func(ctx context.Context, dest M.Socksaddr) (net.Conn, error)
	terminalErr   error
	closeCalled   atomic.Bool
}

func (f *dialTCPFakeNetstack) DialContext(ctx context.Context, dest M.Socksaddr) (net.Conn, error) {
	if f.terminalErr != nil {
		return nil, errors.Join(Errs.Dial, f.terminalErr)
	}
	if f.dial != nil {
		return f.dial(ctx, dest)
	}
	return nil, errors.New("stub dial")
}

func (f *dialTCPFakeNetstack) TerminalError() error { return f.terminalErr }

func (f *dialTCPFakeNetstack) Close() error {
	f.closeCalled.Store(true)
	return nil
}

type dialTCPFakePacketSession struct{}

func (dialTCPFakePacketSession) ReadPacket([]byte) (int, error)  { return 0, errors.New("stub") }
func (dialTCPFakePacketSession) WritePacket([]byte) ([]byte, error) { return nil, errors.New("stub") }
func (dialTCPFakePacketSession) Close() error                      { return nil }

type dialTCPFakeHost struct {
	mu                    sync.Mutex
	fallbackCleared       atomic.Bool
	tcpNetstack           TCPNetstack
	installInflight       atomic.Int32
	openErr               error
	factoryErr            error
	factoryStack          TCPNetstack
	releaseAbandoned      atomic.Int32
	factoryErrorHandled   atomic.Int32
	recordReadyFalse      atomic.Int32
	attachCount           atomic.Int32
	flushCount            atomic.Int32
	ingressStartCount     atomic.Int32
	resetStalePlaneCount  atomic.Int32
	cancelAfterFactory    func()
}

func (h *dialTCPFakeHost) ClearHTTPFallbackAfterGiveUp() {
	h.fallbackCleared.Store(true)
}

func (h *dialTCPFakeHost) LockSession()   { h.mu.Lock() }
func (h *dialTCPFakeHost) UnlockSession() { h.mu.Unlock() }

func (h *dialTCPFakeHost) OpenIPSessionLocked(context.Context) (PacketSession, error) {
	if h.openErr != nil {
		return nil, h.openErr
	}
	return dialTCPFakePacketSession{}, nil
}

func (h *dialTCPFakeHost) TCPNetstack() TCPNetstack { return h.tcpNetstack }

func (h *dialTCPFakeHost) AttachTCPNetstack(ns TCPNetstack) {
	h.tcpNetstack = ns
	h.attachCount.Add(1)
}

func (h *dialTCPFakeHost) FlushTCPNetstackIngress(TCPNetstack) {
	h.flushCount.Add(1)
}

func (h *dialTCPFakeHost) BumpTCPInstallInflight(delta int) {
	h.installInflight.Add(int32(delta))
}

func (h *dialTCPFakeHost) MaybeStartConnectIPIngressLocked() {
	h.ingressStartCount.Add(1)
}

func (h *dialTCPFakeHost) NewTCPNetstack(context.Context, PacketSession) (TCPNetstack, error) {
	if h.factoryErr != nil {
		return nil, h.factoryErr
	}
	var stack TCPNetstack
	if h.factoryStack != nil {
		stack = h.factoryStack
	} else {
		stack = &dialTCPFakeNetstack{}
	}
	if h.cancelAfterFactory != nil {
		h.cancelAfterFactory()
	}
	return stack, nil
}

func (h *dialTCPFakeHost) OnTCPNetstackFactoryError() {
	h.factoryErrorHandled.Add(1)
}

func (h *dialTCPFakeHost) RecordTCPNetstackReady(ready bool) {
	if !ready {
		h.recordReadyFalse.Add(1)
	}
}

func (h *dialTCPFakeHost) ReleaseAbandonedIPSession() {
	h.releaseAbandoned.Add(1)
}

func (h *dialTCPFakeHost) ResetStaleConnectIPPlaneLocked() {
	h.resetStalePlaneCount.Add(1)
}

func TestDialTCPCanceledBeforeNormalizeClearsFallback(t *testing.T) {
	host := &dialTCPFakeHost{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := DialTCP(ctx, host, M.ParseSocksaddrHostPort("127.0.0.1", 443))
	if err == nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
	if !host.fallbackCleared.Load() {
		t.Fatal("expected fallback latch cleared on early cancel")
	}
}

func TestDialTCPCanceledAfterNetstackAttachClearsFallback(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	host := &dialTCPFakeHost{
		factoryStack: &dialTCPFakeNetstack{},
		cancelAfterFactory: cancel,
	}
	_, err := DialTCP(ctx, host, M.ParseSocksaddrHostPort("127.0.0.1", 443))
	if err == nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
	if !host.fallbackCleared.Load() {
		t.Fatal("expected fallback latch cleared on post-attach cancel")
	}
	if host.attachCount.Load() != 1 {
		t.Fatalf("attachCount=%d want 1", host.attachCount.Load())
	}
}

func TestDialTCPFactoryErrorReleasesSessionAndClearsIngress(t *testing.T) {
	host := &dialTCPFakeHost{
		factoryErr: errors.New("factory down"),
	}
	_, err := DialTCP(context.Background(), host, M.ParseSocksaddrHostPort("127.0.0.1", 443))
	if err == nil || err.Error() != "factory down" {
		t.Fatalf("expected factory error, got %v", err)
	}
	if host.factoryErrorHandled.Load() != 1 {
		t.Fatalf("factoryErrorHandled=%d want 1", host.factoryErrorHandled.Load())
	}
	if host.releaseAbandoned.Load() != 1 {
		t.Fatalf("releaseAbandoned=%d want 1", host.releaseAbandoned.Load())
	}
	if host.recordReadyFalse.Load() != 1 {
		t.Fatalf("recordReadyFalse=%d want 1", host.recordReadyFalse.Load())
	}
	if host.installInflight.Load() != 0 {
		t.Fatalf("installInflight=%d want 0", host.installInflight.Load())
	}
	if !host.fallbackCleared.Load() {
		t.Fatal("expected fallback latch cleared on netstack factory failure")
	}
}

func TestDialTCPReusesExistingNetstack(t *testing.T) {
	existing := &dialTCPFakeNetstack{
		dial: func(ctx context.Context, dest M.Socksaddr) (net.Conn, error) {
			client, server := net.Pipe()
			_ = server.Close()
			return client, nil
		},
	}
	host := &dialTCPFakeHost{tcpNetstack: existing}
	conn, err := DialTCP(context.Background(), host, M.ParseSocksaddrHostPort("127.0.0.1", 443))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if conn == nil {
		t.Fatal("expected conn")
	}
	_ = conn.Close()
	if host.attachCount.Load() != 0 {
		t.Fatalf("attachCount=%d want 0 when netstack already present", host.attachCount.Load())
	}
	if host.ingressStartCount.Load() != 1 {
		t.Fatalf("ingressStartCount=%d want 1 when reusing netstack (ingress poke)", host.ingressStartCount.Load())
	}
	if host.flushCount.Load() != 1 {
		t.Fatalf("flushCount=%d want 1 when reusing netstack", host.flushCount.Load())
	}
}

func TestDialTCPRetriesAfterConnectionRefused(t *testing.T) {
	var dials atomic.Int32
	dialFn := func(context.Context, M.Socksaddr) (net.Conn, error) {
		if dials.Add(1) == 1 {
			return nil, syscall.ECONNREFUSED
		}
		client, server := net.Pipe()
		_ = server.Close()
		return client, nil
	}
	stack := &dialTCPFakeNetstack{dial: dialFn}
	host := &dialTCPFakeHost{
		tcpNetstack:  stack,
		factoryStack: stack,
	}
	conn, err := DialTCP(context.Background(), host, M.ParseSocksaddrHostPort("127.0.0.1", 443))
	if err != nil {
		t.Fatalf("expected retry success, got %v (dials=%d)", err, dials.Load())
	}
	_ = conn.Close()
	if dials.Load() != 2 {
		t.Fatalf("dials=%d want 2 (refused then success)", dials.Load())
	}
	if host.attachCount.Load() != 2 {
		t.Fatalf("attachCount=%d want 2 (nil reset + reattach on retry)", host.attachCount.Load())
	}
}

func TestDialTCPNetstackDialFailureClearsFallback(t *testing.T) {
	host := &dialTCPFakeHost{
		tcpNetstack: &dialTCPFakeNetstack{
			dial: func(context.Context, M.Socksaddr) (net.Conn, error) {
				return nil, errors.New("netstack dial permanent")
			},
		},
	}
	_, err := DialTCP(context.Background(), host, M.ParseSocksaddrHostPort("127.0.0.1", 443))
	if err == nil || err.Error() != "netstack dial permanent" {
		t.Fatalf("expected netstack dial error, got %v", err)
	}
	if !host.fallbackCleared.Load() {
		t.Fatal("expected fallback latch cleared on netstack dial failure")
	}
}

func TestDialTCPResetsTerminalNetstackBeforeDial(t *testing.T) {
	var dials atomic.Int32
	stale := &dialTCPFakeNetstack{terminalErr: errors.New("stale plane")}
	fresh := &dialTCPFakeNetstack{
		dial: func(context.Context, M.Socksaddr) (net.Conn, error) {
			if dials.Add(1) == 1 {
				client, server := net.Pipe()
				_ = server.Close()
				return client, nil
			}
			return nil, errors.New("unexpected second dial on same stack")
		},
	}
	host := &dialTCPFakeHost{
		tcpNetstack:  stale,
		factoryStack: fresh,
	}
	conn, err := DialTCP(context.Background(), host, M.ParseSocksaddrHostPort("127.0.0.1", 443))
	if err != nil {
		t.Fatalf("expected retry success after terminal reset, got %v", err)
	}
	_ = conn.Close()
	if !stale.closeCalled.Load() {
		t.Fatal("expected stale netstack closed")
	}
	if host.resetStalePlaneCount.Load() != 1 {
		t.Fatalf("resetStalePlaneCount=%d want 1", host.resetStalePlaneCount.Load())
	}
	if dials.Load() != 1 {
		t.Fatalf("dials=%d want 1 on fresh stack", dials.Load())
	}
}

func TestDialTCPAppliesDefaultTimeoutWithoutDeadline(t *testing.T) {
	started := make(chan struct{})
	host := &dialTCPFakeHost{
		tcpNetstack: &dialTCPFakeNetstack{
			dial: func(ctx context.Context, _ M.Socksaddr) (net.Conn, error) {
				close(started)
				<-ctx.Done()
				return nil, context.Cause(ctx)
			},
		},
	}
	start := time.Now()
	done := make(chan error, 1)
	go func() {
		_, err := DialTCP(context.Background(), host, M.ParseSocksaddrHostPort("127.0.0.1", 443))
		done <- err
	}()
	<-started
	err := <-done
	elapsed := time.Since(start)
	if elapsed < 19*time.Second || elapsed > 26*time.Second {
		t.Fatalf("elapsed %v want ~%v default dial timeout", elapsed, connectIPTCPDialDefaultTimeout)
	}
	if err == nil {
		t.Fatal("expected dial error after default timeout")
	}
}
