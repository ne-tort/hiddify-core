package tun

import (
	"context"
	"log"
	"sync"
	"sync/atomic"
	"time"
)

const nativeL3PlaneReadyPoll = 10 * time.Millisecond

// nativeL3PumpReconnectDelay bounds usque-style pump restart after LoopOut/LoopIn fatal.
const nativeL3PumpReconnectDelay = 50 * time.Millisecond

// NativeL3PlaneSession owns L3 overlay ingress lifecycle (W-IP-ARCH-3 PlaneSession).
// State: Open → StartIngress → Active; Recycle → StopIngress → rebind → RestartIngress.
type NativeL3PlaneSession struct {
	bridge *L3OverlayBridge

	mu           sync.Mutex
	parent       context.Context
	runCtx       context.Context
	cancel       context.CancelFunc
	wg           sync.WaitGroup
	ingressGen   atomic.Uint64
	ingressAlive atomic.Bool
	onReadFatal  func(error)
}

// NewNativeL3PlaneSession wraps an L3 bridge with supervised ingress.
func NewNativeL3PlaneSession(bridge *L3OverlayBridge) *NativeL3PlaneSession {
	return &NativeL3PlaneSession{bridge: bridge}
}

// Bridge returns the underlying L3 overlay bridge.
func (p *NativeL3PlaneSession) Bridge() *L3OverlayBridge {
	if p == nil {
		return nil
	}
	return p.bridge
}

// SetReadFatalHook runs when ingress ReadPacket exits with a non-cancel error.
func (p *NativeL3PlaneSession) SetReadFatalHook(fn func(error)) {
	if p == nil {
		return
	}
	p.onReadFatal = fn
}

// IngressGeneration bumps on each StartIngress / RestartIngress (readiness signal).
func (p *NativeL3PlaneSession) IngressGeneration() uint64 {
	if p == nil {
		return 0
	}
	return p.ingressGen.Load()
}

// StartIngress runs RunPump until StopIngress or parent ctx cancel.
func (p *NativeL3PlaneSession) StartIngress(parent context.Context) {
	if p == nil || p.bridge == nil || parent == nil {
		return
	}
	p.mu.Lock()
	if p.cancel != nil {
		p.cancel()
		p.wg.Wait()
	}
	p.parent = parent
	p.runCtx, p.cancel = context.WithCancel(parent)
	bridge := p.bridge
	gen := p.ingressGen.Add(1)
	p.mu.Unlock()
	p.wg.Add(1)
	p.ingressAlive.Store(true)
	go func() {
		defer p.wg.Done()
		defer p.ingressAlive.Store(false)
		for {
			if p.runCtx.Err() != nil {
				return
			}
			err := bridge.RunPump(p.runCtx)
			if isIngressCancel(err) || p.runCtx.Err() != nil {
				return
			}
			if err != nil && p.onReadFatal != nil {
				p.onReadFatal(err)
			}
			select {
			case <-p.runCtx.Done():
				return
			case <-time.After(nativeL3PumpReconnectDelay):
			}
			log.Printf("masque connect_ip native l3: pump restart after %v", err)
		}
	}()
	log.Printf("masque connect_ip native l3: plane ready gen=%d", gen)
}

// IngressStopped reports whether the supervised pump goroutine has exited (LIFE-4).
func (p *NativeL3PlaneSession) IngressStopped() bool {
	if p == nil {
		return true
	}
	return !p.ingressAlive.Load()
}

// StopIngress cancels the ingress loop and waits for exit.
func (p *NativeL3PlaneSession) StopIngress() {
	if p == nil {
		return
	}
	p.mu.Lock()
	cancel := p.cancel
	p.cancel = nil
	p.mu.Unlock()
	if cancel != nil {
		cancel()
		p.wg.Wait()
	}
}

// RestartIngress stops and restarts ingress on the stored parent context.
func (p *NativeL3PlaneSession) RestartIngress() {
	if p == nil {
		return
	}
	p.mu.Lock()
	parent := p.parent
	p.mu.Unlock()
	if parent == nil {
		return
	}
	p.StopIngress()
	p.StartIngress(parent)
}

// WaitReady blocks until ingress has started at least once or ctx expires.
func (p *NativeL3PlaneSession) WaitReady(ctx context.Context) error {
	if p == nil {
		return context.Canceled
	}
	tick := time.NewTicker(nativeL3PlaneReadyPoll)
	defer tick.Stop()
	for {
		if p.ingressGen.Load() > 0 && p.ingressAlive.Load() {
			return nil
		}
		select {
		case <-ctx.Done():
			return context.Cause(ctx)
		case <-tick.C:
		}
	}
}

func isIngressCancel(err error) bool {
	if err == nil {
		return true
	}
	return err == context.Canceled
}
