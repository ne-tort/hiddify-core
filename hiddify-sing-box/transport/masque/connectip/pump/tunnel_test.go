package pump

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type mockPacketConn struct {
	mu       sync.Mutex
	readCh   chan []byte
	written  [][]byte
	readErr  error
	writeErr error
	closed   bool
}

func newMockPacketConn() *mockPacketConn {
	return &mockPacketConn{readCh: make(chan []byte, 64)}
}

func (m *mockPacketConn) ReadPacket(ctx context.Context, buf []byte) (int, error) {
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return 0, net.ErrClosed
	}
	if m.readErr != nil {
		err := m.readErr
		m.mu.Unlock()
		return 0, err
	}
	m.mu.Unlock()
	select {
	case <-ctx.Done():
		return 0, context.Cause(ctx)
	case pkt, ok := <-m.readCh:
		if !ok {
			return 0, io.EOF
		}
		n := copy(buf, pkt)
		return n, nil
	}
}

func (m *mockPacketConn) WritePacket(buffer []byte) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return nil, net.ErrClosed
	}
	if m.writeErr != nil {
		return nil, m.writeErr
	}
	cp := append([]byte(nil), buffer...)
	m.written = append(m.written, cp)
	return nil, nil
}

func (m *mockPacketConn) WritePacketNoWake(buffer []byte) ([]byte, error) {
	return m.WritePacket(buffer)
}

func (m *mockPacketConn) WritePacketInPlaceNoWake(buffer []byte) ([]byte, bool, error) {
	icmp, err := m.WritePacketNoWake(buffer)
	return icmp, false, err
}

func (m *mockPacketConn) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.closed {
		m.closed = true
		close(m.readCh)
	}
	return nil
}

type mockDevice struct {
	mu          sync.Mutex
	readCh      chan []byte
	written     [][]byte
	readErr     error
	writeErr    error
	drainCalls  int
	closed      bool
}

func newMockDevice() *mockDevice {
	return &mockDevice{readCh: make(chan []byte, 64)}
}

func (d *mockDevice) ReadPacket(ctx context.Context, buf []byte) (int, error) {
	d.mu.Lock()
	if d.closed {
		d.mu.Unlock()
		return 0, errors.New("device closed")
	}
	if d.readErr != nil {
		err := d.readErr
		d.mu.Unlock()
		return 0, err
	}
	d.mu.Unlock()
	select {
	case <-ctx.Done():
		return 0, context.Cause(ctx)
	case pkt, ok := <-d.readCh:
		if !ok {
			return 0, io.EOF
		}
		n := copy(buf, pkt)
		return n, nil
	}
}

func (d *mockDevice) WritePacket(pkt []byte) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return errors.New("device closed")
	}
	if d.writeErr != nil {
		return d.writeErr
	}
	d.written = append(d.written, append([]byte(nil), pkt...))
	return nil
}

func (d *mockDevice) ScheduleOutboundDrain() {
	d.mu.Lock()
	d.drainCalls++
	d.mu.Unlock()
}

func (d *mockDevice) Close() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if !d.closed {
		d.closed = true
		close(d.readCh)
	}
	return nil
}

func TestRunTunnelLoopInForwardsToConn(t *testing.T) {
	t.Parallel()
	dev := newMockDevice()
	conn := newMockPacketConn()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		dev.readCh <- []byte{1, 2, 3}
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()
	err := RunTunnel(ctx, dev, conn, TunnelOptions{})
	if err != nil && !errors.Is(err, context.Canceled) {
		t.Fatalf("RunTunnel: %v", err)
	}
	conn.mu.Lock()
	defer conn.mu.Unlock()
	if len(conn.written) != 1 || conn.written[0][0] != 1 {
		t.Fatalf("conn written = %#v", conn.written)
	}
}

func TestNormalizeTunnelOptionsUsqueDefault(t *testing.T) {
	t.Parallel()
	opts := NormalizeTunnelOptions(TunnelOptions{})
	if !opts.LoopOutUsqueImmediate {
		t.Fatalf("expected LoopOutUsqueImmediate default: %+v", opts)
	}
}

func TestRunTunnelICMPEchoReply(t *testing.T) {
	t.Parallel()
	dev := newMockDevice()
	conn := newMockPacketConn()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		dev.readCh <- []byte{0x01}
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()
	origWrite := conn.WritePacket
	conn.writeErr = nil
	_ = origWrite
	// Override WritePacket to return ICMP echo reply.
	type icmpConn struct {
		*mockPacketConn
	}
	// Patch via embedding: replace mock with custom conn.
	icmpMock := &icmpReturningConn{mockPacketConn: conn, icmp: []byte{0x99}}
	err := RunTunnel(ctx, dev, icmpMock, TunnelOptions{})
	if err != nil && !errors.Is(err, context.Canceled) {
		t.Fatalf("RunTunnel: %v", err)
	}
	dev.mu.Lock()
	defer dev.mu.Unlock()
	if len(dev.written) != 1 || dev.written[0][0] != 0x99 {
		t.Fatalf("ICMP echo not written back to device: %#v", dev.written)
	}
}

type icmpReturningConn struct {
	*mockPacketConn
	icmp []byte
}

func (c *icmpReturningConn) WritePacket(buffer []byte) ([]byte, error) {
	icmp, err := c.mockPacketConn.WritePacket(buffer)
	if err != nil {
		return icmp, err
	}
	return c.icmp, nil
}

func (c *icmpReturningConn) WritePacketInPlaceNoWake(buffer []byte) ([]byte, bool, error) {
	icmp, err := c.WritePacket(buffer)
	return icmp, false, err
}

func TestRunTunnelSupervisorCancel(t *testing.T) {
	t.Parallel()
	dev := newMockDevice()
	conn := newMockPacketConn()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = RunTunnel(ctx, dev, conn, TunnelOptions{})
	}()
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("RunTunnel did not exit after cancel")
	}
	dev.mu.Lock()
	closed := dev.closed
	dev.mu.Unlock()
	if closed {
		t.Fatal("RunTunnel must not Close device (PlaneSession owns lifecycle; usque parity)")
	}
}

func TestRunTunnelLeavesDeviceOpenOnLoopOutError(t *testing.T) {
	t.Parallel()
	dev := newMockDevice()
	conn := newMockPacketConn()
	conn.readErr = io.EOF
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_ = RunTunnel(ctx, dev, conn, TunnelOptions{})
	dev.mu.Lock()
	closed := dev.closed
	dev.mu.Unlock()
	if closed {
		t.Fatal("device closed on loop error")
	}
}

func TestRunTunnelFlushWakeOnLoopOut(t *testing.T) {
	t.Parallel()
	dev := newMockDevice()
	conn := newMockPacketConn()
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	wakePending := true
	conn.readCh <- []byte{0x01}
	opts := TunnelOptions{
		Wake: WakeHooks{
			TakeIngressWakePending: func() bool {
				if !wakePending {
					return false
				}
				wakePending = false
				return true
			},
			PokeEgressTransport: func() {},
		},
	}
	go func() {
		_ = RunTunnel(ctx, dev, conn, opts)
	}()
	time.Sleep(80 * time.Millisecond)
	dev.mu.Lock()
	drains := dev.drainCalls
	dev.mu.Unlock()
	if drains == 0 {
		t.Fatal("expected ScheduleOutboundDrain after LoopOut batch")
	}
}

func TestConnectIPArchGuardOutboundDrainDeviceOptional(t *testing.T) {
	t.Parallel()
	var dev OutboundDrainDevice = (*mockDevice)(nil)
	_ = dev
}

// queuedPacketConn returns one datagram per ReadPacket; tryCtx reads also dequeue (batch-drain parity).
type queuedPacketConn struct {
	mu    sync.Mutex
	queue [][]byte
}

func (q *queuedPacketConn) ReadPacket(ctx context.Context, buf []byte) (int, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if len(q.queue) == 0 {
		select {
		case <-ctx.Done():
			return 0, context.Cause(ctx)
		default:
			return 0, nil
		}
	}
	pkt := q.queue[0]
	q.queue = q.queue[1:]
	return copy(buf, pkt), nil
}

func (q *queuedPacketConn) WritePacket([]byte) ([]byte, error) { return nil, nil }
func (q *queuedPacketConn) WritePacketNoWake([]byte) ([]byte, error) {
	return nil, nil
}
func (q *queuedPacketConn) WritePacketInPlaceNoWake([]byte) ([]byte, bool, error) {
	return nil, false, nil
}
func (q *queuedPacketConn) Close() error { return nil }

func (q *queuedPacketConn) push(pkts ...[]byte) {
	q.mu.Lock()
	q.queue = append(q.queue, pkts...)
	q.mu.Unlock()
}

// TestRunTunnelLoopInSingleRead verifies usque parity: one blocking ReadPacket per LoopIn iter.
func TestRunTunnelLoopInSingleRead(t *testing.T) {
	t.Parallel()
	dev := &loopInCountDevice{}
	conn := &queuedPacketConn{}
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	go func() {
		_ = RunTunnel(ctx, dev, conn, TunnelOptions{})
	}()
	deadline := time.Now().Add(150 * time.Millisecond)
	for time.Now().Before(deadline) {
		if dev.readCalls.Load() >= 3 {
			break
		}
		time.Sleep(time.Millisecond)
	}
	if dev.readCalls.Load() < 3 {
		t.Fatalf("readCalls=%d want >=3 (one blocking read per LoopIn iter)", dev.readCalls.Load())
	}
}

type loopInCountDevice struct {
	readCalls atomic.Int32
}

func (d *loopInCountDevice) ReadPacket(ctx context.Context, buf []byte) (int, error) {
	d.readCalls.Add(1)
	select {
	case <-ctx.Done():
		return 0, context.Cause(ctx)
	case <-time.After(time.Millisecond):
	}
	if len(buf) == 0 {
		return 0, nil
	}
	buf[0] = 1
	return 1, nil
}

func (d *loopInCountDevice) WritePacket([]byte) error { return nil }
func (d *loopInCountDevice) Close() error             { return nil }

// TestRunTunnelLoopOutUsqueImmediateSingleDatagram verifies usque parity: no zero-timeout
// coalesce on LoopOut (WriteIngress must not starve LoopIn ReadHostEgress).
func TestRunTunnelLoopOutUsqueImmediateSingleDatagram(t *testing.T) {
	t.Parallel()
	dev := newMockDevice()
	conn := &queuedPacketConn{}
	for i := 0; i < 4; i++ {
		conn.push([]byte{byte(i)})
	}
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	go func() {
		_ = RunTunnel(ctx, dev, conn, TunnelOptions{LoopOutUsqueImmediate: true})
	}()
	deadline := time.Now().Add(150 * time.Millisecond)
	for time.Now().Before(deadline) {
		dev.mu.Lock()
		n := len(dev.written)
		dev.mu.Unlock()
		if n >= 4 {
			break
		}
		time.Sleep(time.Millisecond)
	}
	dev.mu.Lock()
	n := len(dev.written)
	dev.mu.Unlock()
	if n != 4 {
		t.Fatalf("written=%d want 4 (one datagram per LoopOut iter)", n)
	}
}

func TestRunTunnelDefaultUsqueLoopOutSingleDatagram(t *testing.T) {
	t.Parallel()
	dev := newMockDevice()
	conn := &queuedPacketConn{}
	for i := 0; i < 4; i++ {
		conn.push([]byte{byte(i)})
	}
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	go func() {
		_ = RunTunnel(ctx, dev, conn, TunnelOptions{})
	}()
	deadline := time.Now().Add(150 * time.Millisecond)
	for time.Now().Before(deadline) {
		dev.mu.Lock()
		n := len(dev.written)
		dev.mu.Unlock()
		if n >= 4 {
			break
		}
		time.Sleep(time.Millisecond)
	}
	dev.mu.Lock()
	n := len(dev.written)
	dev.mu.Unlock()
	if n != 4 {
		t.Fatalf("default opts written=%d want 4 (usque one datagram per LoopOut iter)", n)
	}
}

func TestPumpRunTunnelMatchesUsqueImmediateDefaults(t *testing.T) {
	t.Parallel()
	for _, opts := range []TunnelOptions{UsqueTunnelOptions(), NormalizeTunnelOptions(TunnelOptions{})} {
		if !opts.LoopOutUsqueImmediate {
			t.Fatalf("usque defaults: LoopOutImmediate=%v want true", opts.LoopOutUsqueImmediate)
		}
	}
}

func TestRunTunnelLoopOutWakePerPacketUsqueImmediate(t *testing.T) {
	t.Parallel()
	dev := newMockDevice()
	conn := &queuedPacketConn{}
	conn.push([]byte{1}, []byte{2}, []byte{3})
	var loopOutEnd atomic.Int32
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	_ = RunTunnel(ctx, dev, conn, TunnelOptions{
		OnLoopOutEnd: func(TunnelDevice) { loopOutEnd.Add(1) },
	})
	if got := loopOutEnd.Load(); got != 3 {
		t.Fatalf("loopOutEnd=%d want 3 (usque immediate: one wake per datagram)", got)
	}
}

type inPlacePacketConn struct {
	retainNext bool
	writes     atomic.Int32
}

func (c *inPlacePacketConn) ReadPacket(context.Context, []byte) (int, error) {
	return 0, nil
}

func (c *inPlacePacketConn) WritePacket([]byte) ([]byte, error) {
	return nil, nil
}

func (c *inPlacePacketConn) Close() error { return nil }

func (c *inPlacePacketConn) WritePacketNoWake([]byte) ([]byte, error) {
	c.writes.Add(1)
	return nil, nil
}

func (c *inPlacePacketConn) WritePacketInPlaceNoWake(_ []byte) ([]byte, bool, error) {
	c.writes.Add(1)
	return nil, c.retainNext, nil
}

func TestRunTunnelLoopInRetainedBufferGetsFreshPoolSlice(t *testing.T) {
	t.Parallel()
	dev := &loopInCountDevice{}
	conn := &inPlacePacketConn{retainNext: true}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	pool := NewNetBuffer(128)
	_ = runLoopIn(ctx, dev, conn, TunnelOptions{}, pool)
	if conn.writes.Load() < 1 {
		t.Fatalf("writes=%d want >=1", conn.writes.Load())
	}
	if dev.readCalls.Load() < 2 {
		t.Fatalf("readCalls=%d want >=2 (fresh buf after retained in-place write)", dev.readCalls.Load())
	}
}
