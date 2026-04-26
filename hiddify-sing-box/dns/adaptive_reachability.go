package dns

import (
	"context"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

const (
	adaptiveProbePort    = 443
	adaptiveProbeTimeout = 400 * time.Millisecond
)

var (
	adaptiveProbeIPv4 = netip.MustParseAddr("1.1.1.1")
	adaptiveProbeIPv6 = netip.MustParseAddr("2606:4700:4700::1111")
)

// EffectiveAdaptiveStrategy maps parallel reachability probes to a concrete DNS domain strategy (for tests and docs).
//
// Semantics:
//   - Both paths OK: PreferIPv4 — avoid returning AAAA-first behavior when IPv4 is the common denominator.
//   - Only IPv4 OK: IPv4Only — typical “VPS has no/broken IPv6” case.
//   - Only IPv6 OK: IPv6Only — rare (e.g. NAT64-only client).
//   - Neither OK: IPv4Only — conservative default when outbound is not ready, probes time out, or both fail;
//     avoids AsIS which would still return A+AAAA and can hang or pick broken IPv6 first.
func EffectiveAdaptiveStrategy(v4OK, v6OK bool) C.DomainStrategy {
	switch {
	case v4OK && v6OK:
		return C.DomainStrategyPreferIPv4
	case v4OK && !v6OK:
		return C.DomainStrategyIPv4Only
	case !v4OK && v6OK:
		return C.DomainStrategyIPv6Only
	default:
		return C.DomainStrategyIPv4Only
	}
}

type adaptiveReachability struct {
	mu        sync.Mutex
	cond      *sync.Cond
	logger    logger.ContextLogger
	outbounds adapter.OutboundManager

	valid   bool
	probing bool
	// insideProbe: probe() is on the stack (Dial may synchronously trigger more DNS). Nested
	// effectiveStrategy must not wait or recurse into another probe (deadlock / storm).
	insideProbe int32
	v4OK        bool
	v6OK        bool
}

func newAdaptiveReachability(log logger.ContextLogger, ob adapter.OutboundManager) *adaptiveReachability {
	if ob == nil {
		return nil
	}
	a := &adaptiveReachability{logger: log, outbounds: ob}
	a.cond = sync.NewCond(&a.mu)
	return a
}

func (a *adaptiveReachability) invalidate() {
	if a == nil {
		return
	}
	a.mu.Lock()
	a.valid = false
	a.probing = false
	a.cond.Broadcast()
	a.mu.Unlock()
}

func (a *adaptiveReachability) effectiveStrategy() C.DomainStrategy {
	if a == nil {
		return C.DomainStrategyAsIS
	}
	// Re-entrant DNS while TCP probe runs: return a fixed strategy without nesting probe/singleflight deadlock.
	if atomic.LoadInt32(&a.insideProbe) != 0 {
		return C.DomainStrategyIPv4Only
	}

	a.mu.Lock()
	for {
		if a.valid {
			s := EffectiveAdaptiveStrategy(a.v4OK, a.v6OK)
			a.mu.Unlock()
			return s
		}
		if !a.probing {
			break
		}
		a.cond.Wait()
	}
	a.probing = true
	a.mu.Unlock()

	v4, v6 := a.probe()

	a.mu.Lock()
	a.v4OK, a.v6OK = v4, v6
	a.valid = true
	a.probing = false
	eff := EffectiveAdaptiveStrategy(v4, v6)
	if a.logger != nil {
		a.logger.Debug("dns adaptive reachability: ipv4=", v4, " ipv6=", v6, " -> strategy=", eff, " (sticky until ResetNetwork)")
	}
	a.cond.Broadcast()
	a.mu.Unlock()
	return eff
}

func (a *adaptiveReachability) probe() (v4OK bool, v6OK bool) {
	atomic.AddInt32(&a.insideProbe, 1)
	defer atomic.AddInt32(&a.insideProbe, -1)

	ob := a.outbounds.Default()
	if ob == nil || !ob.IsReady() {
		return false, false
	}
	ctx, cancel := context.WithTimeout(context.Background(), adaptiveProbeTimeout)
	defer cancel()
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		v4OK = a.probeAddr(ctx, ob, adaptiveProbeIPv4)
	}()
	go func() {
		defer wg.Done()
		v6OK = a.probeAddr(ctx, ob, adaptiveProbeIPv6)
	}()
	wg.Wait()
	return v4OK, v6OK
}

func (a *adaptiveReachability) probeAddr(ctx context.Context, ob adapter.Outbound, addr netip.Addr) bool {
	conn, err := ob.DialContext(ctx, N.NetworkTCP, M.SocksaddrFrom(addr, adaptiveProbePort))
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}
