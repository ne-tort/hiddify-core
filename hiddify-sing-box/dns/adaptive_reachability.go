package dns

import (
	"context"
	"net/netip"
	"sync"
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
	adaptiveCacheTTL     = 50 * time.Second
)

var (
	adaptiveProbeIPv4 = netip.MustParseAddr("1.1.1.1")
	adaptiveProbeIPv6 = netip.MustParseAddr("2606:4700:4700::1111")
)

// EffectiveAdaptiveStrategy maps parallel reachability probes to a concrete DNS domain strategy (for tests and docs).
func EffectiveAdaptiveStrategy(v4OK, v6OK bool) C.DomainStrategy {
	switch {
	case v4OK && v6OK:
		return C.DomainStrategyAsIS
	case v4OK && !v6OK:
		return C.DomainStrategyIPv4Only
	case !v4OK && v6OK:
		return C.DomainStrategyIPv6Only
	default:
		return C.DomainStrategyAsIS
	}
}

type adaptiveReachability struct {
	mu        sync.Mutex
	logger    logger.ContextLogger
	outbounds adapter.OutboundManager

	valid   bool
	expires time.Time
	v4OK    bool
	v6OK    bool
}

func newAdaptiveReachability(log logger.ContextLogger, ob adapter.OutboundManager) *adaptiveReachability {
	if ob == nil {
		return nil
	}
	return &adaptiveReachability{logger: log, outbounds: ob}
}

func (a *adaptiveReachability) invalidate() {
	if a == nil {
		return
	}
	a.mu.Lock()
	a.valid = false
	a.mu.Unlock()
}

func (a *adaptiveReachability) effectiveStrategy() C.DomainStrategy {
	if a == nil {
		return C.DomainStrategyAsIS
	}
	now := time.Now()
	a.mu.Lock()
	if a.valid && now.Before(a.expires) {
		s := EffectiveAdaptiveStrategy(a.v4OK, a.v6OK)
		a.mu.Unlock()
		return s
	}
	a.mu.Unlock()

	a.mu.Lock()
	defer a.mu.Unlock()
	now = time.Now()
	if a.valid && now.Before(a.expires) {
		return EffectiveAdaptiveStrategy(a.v4OK, a.v6OK)
	}
	v4, v6 := a.probe()
	a.v4OK, a.v6OK = v4, v6
	a.valid = true
	a.expires = time.Now().Add(adaptiveCacheTTL)
	eff := EffectiveAdaptiveStrategy(v4, v6)
	if a.logger != nil {
		a.logger.Debug("dns adaptive reachability: ipv4=", v4, " ipv6=", v6, " -> strategy=", eff)
	}
	return eff
}

func (a *adaptiveReachability) probe() (v4OK bool, v6OK bool) {
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
