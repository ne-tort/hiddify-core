package pump

import (
	"context"
	"errors"
	"io"
	"log"
	"net"
	"runtime"
	"sync"
	"time"

	connectip "github.com/quic-go/connect-ip-go"
)

// TunnelOptions configures RunTunnel (usque MaintainTunnel pump + R2 flush/wake extensions).
type TunnelOptions struct {
	MTU int
	// OnLoopInEnd runs once per LoopIn iteration after WritePacket (typically FlushEgressBatch).
	OnLoopInEnd func()
	// Demux handles TCP inject / UDP bridge on LoopOut (CM path); nil for raw IP inject (TUN L3).
	Demux TunnelDemux
	// Wake configures LoopOut end-of-iteration ingress ACK wake.
	Wake WakeHooks
	// OnLoopOutEnd runs once per LoopOut batch after demux/inject (defaults to FlushIngressAckWake).
	OnLoopOutEnd func(device TunnelDevice)
	// NetBuffer overrides the default MTU pool; nil uses DefaultTunnelMTU.
	NetBuffer *NetBuffer
	// LoopOutUsqueImmediate skips blocking batch drain (usque: one ReadPacket → WritePacket per iteration).
	LoopOutUsqueImmediate bool
	// LoopInUsqueImmediate skips zero-timeout coalesce after ReadPacket (usque: one read → one wire write).
	LoopInUsqueImmediate bool
	// LoopOutSkipBatchDrain skips the 2ms blocking batch window (host-kernel: coalesce wire only).
	LoopOutSkipBatchDrain bool
	// LoopInObserver collects per-iteration read/write/flush metrics (tests/diagnostics only).
	LoopInObserver *LoopInObserver
}

// UsqueTunnelOptions returns MaintainTunnel-shaped pump defaults (one read → one write both loops).
func UsqueTunnelOptions() TunnelOptions {
	return TunnelOptions{
		LoopOutUsqueImmediate: true,
		LoopInUsqueImmediate:  true,
	}
}

// NormalizeTunnelOptions applies usque immediate defaults (prod always one read → one write).
func NormalizeTunnelOptions(opts TunnelOptions) TunnelOptions {
	opts.LoopOutUsqueImmediate = true
	opts.LoopInUsqueImmediate = true
	return opts
}

// TunnelDemux splits ingress IP frames before Device.WritePacket (CM netstack path).
type TunnelDemux interface {
	DispatchIngress(ctx context.Context, pkt []byte) error
}

// RunTunnel starts symmetric Device↔Conn pump loops until ctx is cancelled or a loop errors.
// Ref: experiments/router/stand/usque/api/tunnel.go MaintainTunnel forwarding goroutines.
func RunTunnel(ctx context.Context, device TunnelDevice, conn PacketConn, opts TunnelOptions) error {
	if device == nil || conn == nil {
		return nil
	}
	opts = NormalizeTunnelOptions(opts)
	mtu := opts.MTU
	if mtu <= 0 {
		mtu = DefaultTunnelMTU
	}
	pool := opts.NetBuffer
	if pool == nil {
		pool = NewNetBuffer(mtu)
	}
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	errCh := make(chan error, 2)
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		errCh <- runLoopIn(runCtx, device, conn, opts, pool)
	}()
	go func() {
		defer wg.Done()
		errCh <- runLoopOut(runCtx, device, conn, opts, pool)
	}()
	var firstErr error
	select {
	case firstErr = <-errCh:
		cancel()
	case <-runCtx.Done():
		firstErr = context.Cause(runCtx)
	}
	wg.Wait()
	_ = conn.Close()
	if firstErr != nil && !errors.Is(firstErr, context.Canceled) {
		return firstErr
	}
	return context.Cause(ctx)
}

func dispatchLoopOutFrame(ctx context.Context, device TunnelDevice, opts TunnelOptions, pkt []byte) error {
	if opts.Demux != nil {
		return opts.Demux.DispatchIngress(ctx, pkt)
	}
	return device.WritePacket(pkt)
}

func runLoopIn(ctx context.Context, device TunnelDevice, conn PacketConn, opts TunnelOptions, pool *NetBuffer) error {
	var buf []byte
	releaseBuf := func() {
		if buf != nil {
			pool.Put(buf)
			buf = nil
		}
	}
	defer releaseBuf()
	obs := opts.LoopInObserver
	writeOne := func(n int) error {
		var wStart time.Time
		if obs != nil {
			wStart = time.Now()
		}
		retained, err := writeLoopInPacket(device, conn, buf[:n])
		if obs != nil {
			obs.recordWrite(time.Since(wStart))
			obs.recordPkt()
		}
		if err != nil {
			return err
		}
		if retained {
			buf = nil
		}
		return nil
	}
	for {
		if ctx.Err() != nil {
			return context.Cause(ctx)
		}
		if buf == nil {
			buf = pool.Get()
		}
		var rStart time.Time
		if obs != nil {
			rStart = time.Now()
		}
		n, err := device.ReadPacket(ctx, buf)
		if obs != nil {
			obs.recordRead(time.Since(rStart))
		}
		if err != nil {
			if ctx.Err() != nil {
				return context.Cause(ctx)
			}
			if IsRetryablePacketReadError(err) {
				runtime.Gosched()
				continue
			}
			return err
		}
		if n <= 0 {
			runtime.Gosched()
			continue
		}
		if err := writeOne(n); err != nil {
			return err
		}
		if opts.OnLoopInEnd != nil {
			var flushStart time.Time
			if obs != nil {
				flushStart = time.Now()
			}
			opts.OnLoopInEnd()
			if obs != nil {
				obs.recordFlush(time.Since(flushStart))
			}
		}
		if obs != nil {
			obs.endIter()
		}
	}
}

// PacketConnNoWake extends PacketConn with batched wire enqueue (caller flushes via OnLoopInEnd).
type PacketConnNoWake interface {
	PacketConn
	WritePacketNoWake(buffer []byte) (icmp []byte, err error)
}

// PacketConnInPlaceNoWake extends PacketConnNoWake with zero-copy pump pool writes when QUIC retains buf.
type PacketConnInPlaceNoWake interface {
	PacketConnNoWake
	WritePacketInPlaceNoWake(buffer []byte) (icmp []byte, retained bool, err error)
}

// writeLoopInPacket sends one egress datagram to wire (usque ipConn.WritePacket parity).
// retained=true when the wire layer keeps pkt; caller must not reuse the slice.
// CloseError is fatal; other write errors are logged and skipped without stopping the pump.
func writeLoopInPacket(device TunnelDevice, conn PacketConn, pkt []byte) (retained bool, err error) {
	var icmp []byte
	if ip, ok := conn.(PacketConnInPlaceNoWake); ok {
		icmp, retained, err = ip.WritePacketInPlaceNoWake(pkt)
	} else {
		icmp, err = conn.WritePacket(pkt)
	}
	if err != nil {
		if errors.As(err, new(*connectip.CloseError)) {
			return retained, err
		}
		log.Printf("connect-ip pump: error writing to wire: %v, continuing...", err)
		return retained, nil
	}
	if len(icmp) > 0 {
		if err := device.WritePacket(icmp); err != nil {
			if errors.As(err, new(*connectip.CloseError)) {
				return retained, err
			}
			log.Printf("connect-ip pump: error writing ICMP to device: %v, continuing...", err)
		}
	}
	return retained, nil
}

func runLoopOut(ctx context.Context, device TunnelDevice, conn PacketConn, opts TunnelOptions, pool *NetBuffer) error {
	buf := pool.Get()
	defer pool.Put(buf)
	tryCtx, tryCancel := context.WithTimeout(ctx, 0)
	defer tryCancel()
	flushWake := func() {
		if opts.OnLoopOutEnd != nil {
			opts.OnLoopOutEnd(device)
			return
		}
		FlushIngressAckWake(device, opts.Wake)
	}
	for {
		if ctx.Err() != nil {
			return context.Cause(ctx)
		}
		n, err := conn.ReadPacket(ctx, buf)
		if err != nil {
			if err == io.EOF || err == net.ErrClosed {
				return err
			}
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return context.Cause(ctx)
			}
			if errors.As(err, new(*connectip.CloseError)) {
				return err
			}
			if IsRetryablePacketReadError(err) {
				log.Printf("connect-ip pump: retryable read error: %v, continuing...", err)
				continue
			}
			return err
		}
		if n <= 0 {
			continue
		}
		if err := dispatchLoopOutFrame(ctx, device, opts, buf[:n]); err != nil {
			return err
		}
		// usque LoopOut: one wire datagram → one WritePacket per iteration (no zero-timeout coalesce).
		// Batching WriteIngress starves LoopIn ReadHostEgress → tun ENOBUFS / kernel TCP stall (iperf -R).
		if !opts.LoopOutUsqueImmediate {
			for {
				n2, err2 := conn.ReadPacket(tryCtx, buf)
				if err2 != nil || n2 <= 0 {
					break
				}
				if err := dispatchLoopOutFrame(ctx, device, opts, buf[:n2]); err != nil {
					return err
				}
			}
		}
		flushWake()
	}
}
