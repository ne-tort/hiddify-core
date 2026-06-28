package netstack

import (
	"context"
	"errors"
	"io"

	"github.com/sagernet/gvisor/pkg/tcpip/stack"
)

// DeviceAdapter implements pump.TunnelDevice over the CONNECT-IP client gVisor netstack.
type DeviceAdapter struct {
	ns *Netstack
}

// NewDeviceAdapter wraps ns for usque-shaped pump RunTunnel LoopIn/LoopOut.
func NewDeviceAdapter(ns *Netstack) *DeviceAdapter {
	return &DeviceAdapter{ns: ns}
}

// ReadPacket drains one outbound IP frame from the gVisor link endpoint (LoopIn source).
func (d *DeviceAdapter) ReadPacket(ctx context.Context, buf []byte) (int, error) {
	if d == nil || d.ns == nil {
		return 0, errors.New("connect-ip netstack device: nil")
	}
	for {
		if err := d.ns.waitCtx(ctx); err != nil {
			return 0, err
		}
		pkt := d.ns.readOutboundFrame()
		if pkt != nil {
			defer pkt.DecRef()
			view := pkt.ToView()
			slice := view.AsSlice()
			if len(slice) > len(buf) {
				return 0, io.ErrShortBuffer
			}
			copy(buf, slice)
			return len(slice), nil
		}
		if ctx.Err() != nil {
			return 0, context.Cause(ctx)
		}
		if !d.ns.pumpLoopActive.Load() {
			d.ns.ScheduleOutboundDrain()
		}
		select {
		case <-ctx.Done():
			return 0, context.Cause(ctx)
		case <-d.ns.egressWake:
		}
	}
}

// WritePacket injects one ingress IP frame (LoopOut without demux; wake via demux FlushWake).
func (d *DeviceAdapter) WritePacket(pkt []byte) error {
	if d == nil || d.ns == nil {
		return errors.New("connect-ip netstack device: nil")
	}
	d.ns.InjectInboundOwned(pkt)
	return nil
}

// Close closes the underlying netstack.
func (d *DeviceAdapter) Close() error {
	if d == nil || d.ns == nil {
		return nil
	}
	return d.ns.Close()
}

// ScheduleOutboundDrain nudges gVisor egress after ingress ACK wake (RunTunnel LoopOut end).
func (d *DeviceAdapter) ScheduleOutboundDrain() {
	if d == nil || d.ns == nil {
		return
	}
	d.ns.ScheduleOutboundDrain()
}

func (s *Netstack) readOutboundFrame() *stack.PacketBuffer {
	if s == nil || s.endpoint == nil || s.closed.Load() {
		return nil
	}
	return s.endpoint.Read()
}

func (s *Netstack) waitCtx(ctx context.Context) error {
	if ctx == nil {
		return nil
	}
	select {
	case <-ctx.Done():
		return context.Cause(ctx)
	default:
		return nil
	}
}
