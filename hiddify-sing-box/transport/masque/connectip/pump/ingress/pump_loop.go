package ingress

import (
	"context"
	"errors"
	"io"
	"net"
	"runtime"
	"sync"
	"time"

	cipnet "github.com/sagernet/sing-box/transport/masque/connectip/netstack"
	cippump "github.com/sagernet/sing-box/transport/masque/connectip/pump"
)

const dynamicPumpIdlePoll = 2 * time.Millisecond

type pumpNetstack interface {
	SetPumpLoopActive(bool)
	PumpTunnelDevice() *cipnet.DeviceAdapter
}

type idlePumpDevice struct{}

func (idlePumpDevice) ReadPacket(ctx context.Context, _ []byte) (int, error) {
	<-ctx.Done()
	return 0, context.Cause(ctx)
}

func (idlePumpDevice) WritePacket(pkt []byte) error {
	if len(pkt) == 0 {
		return nil
	}
	return nil
}

func (idlePumpDevice) Close() error { return nil }

type dynamicPumpDevice struct {
	host Host

	mu      sync.Mutex
	active  pumpNetstack
	adapter cippump.TunnelDevice
}

func (d *dynamicPumpDevice) ReadPacket(ctx context.Context, buf []byte) (int, error) {
	if dev := d.resolveLoopInDevice(); dev != nil {
		return dev.ReadPacket(ctx, buf)
	}
	timer := time.NewTimer(dynamicPumpIdlePoll)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return 0, context.Cause(ctx)
	case <-timer.C:
		return 0, nil
	}
}

func (d *dynamicPumpDevice) WritePacket(pkt []byte) error {
	dev := d.resolveLoopInDevice()
	if dev == nil {
		return idlePumpDevice{}.WritePacket(pkt)
	}
	return dev.WritePacket(pkt)
}

func (d *dynamicPumpDevice) ScheduleOutboundDrain() {
	dev := d.resolveLoopInDevice()
	if od, ok := dev.(cippump.OutboundDrainDevice); ok {
		od.ScheduleOutboundDrain()
	}
}

func (d *dynamicPumpDevice) Close() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.active != nil {
		d.active.SetPumpLoopActive(false)
		d.active = nil
		d.adapter = nil
	}
	return nil
}

func (d *dynamicPumpDevice) resolveLoopInDevice() cippump.TunnelDevice {
	if d.host != nil && d.host.IngressTCPInstallInflight() {
		d.mu.Lock()
		adapter := d.adapter
		d.mu.Unlock()
		if adapter != nil {
			return adapter
		}
	}
	ns := d.host.IngressTCPNetstackForInject()
	if ns == nil {
		d.clearActive()
		return nil
	}
	impl, ok := ns.(pumpNetstack)
	if !ok || impl == nil {
		d.clearActive()
		return nil
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.active != impl {
		if d.active != nil {
			d.active.SetPumpLoopActive(false)
		}
		d.active = impl
		d.adapter = impl.PumpTunnelDevice()
		d.active.SetPumpLoopActive(true)
	}
	return d.adapter
}

func (d *dynamicPumpDevice) clearActive() {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.active != nil {
		d.active.SetPumpLoopActive(false)
		d.active = nil
		d.adapter = nil
	}
}

type hostPacketConn struct {
	read  func(context.Context, []byte) (int, error)
	write func([]byte) ([]byte, error)
}

func (c *hostPacketConn) ReadPacket(ctx context.Context, buf []byte) (int, error) {
	if c == nil || c.read == nil {
		return 0, net.ErrClosed
	}
	return c.read(ctx, buf)
}

func (c *hostPacketConn) WritePacket(buffer []byte) ([]byte, error) {
	if c == nil || c.write == nil {
		return nil, net.ErrClosed
	}
	return c.write(buffer)
}

func (c *hostPacketConn) Close() error { return nil }

func (ing *Ingress) runPumpLoop(ctx context.Context) {
	defer func() {
		ing.loopMu.Lock()
		ing.running.Store(false)
		ing.wg.Done()
		ing.loopMu.Unlock()
	}()
	for {
		if ctx.Err() != nil {
			return
		}
		err := ing.runOnePump(ctx)
		if ctx.Err() != nil {
			return
		}
		if err == nil {
			return
		}
		if isRetryablePacketReadError(err) {
			runtime.Gosched()
			continue
		}
		if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
			ing.host.IngressObsEvent("ingress_read_closed")
			return
		}
		ing.host.IngressReadDrop("fatal_read_error")
		ing.host.IngressSessionReset("ingress_read_exit")
		ing.host.IngressOnReadFatal(err)
		return
	}
}

func (ing *Ingress) runOnePump(ctx context.Context) error {
	reader := ing.host.IngressPacketReader()
	writer := ing.host.IngressWritePacket()
	if reader == nil || writer == nil {
		return nil
	}
	conn := &hostPacketConn{read: reader, write: writer}
	device := &dynamicPumpDevice{host: ing.host}
	demux := &cippump.IngressDemux{Dispatch: ing.dispatchIngressFrame}
	return cippump.RunTunnel(ctx, device, conn, cippump.TunnelOptions{
		Demux: demux,
		OnLoopInEnd: func() {
			ing.host.IngressFlushEgressBatch()
		},
		OnLoopOutEnd: func(_ cippump.TunnelDevice) {
			ing.host.IngressFlushAckWake()
		},
	})
}

var (
	_ cippump.TunnelDevice        = (*dynamicPumpDevice)(nil)
	_ cippump.OutboundDrainDevice = (*dynamicPumpDevice)(nil)
	_ cippump.PacketConn          = (*hostPacketConn)(nil)
)

// Compile-time check that netstack satisfies pump loop hooks.
var _ pumpNetstack = (*cipnet.Netstack)(nil)
