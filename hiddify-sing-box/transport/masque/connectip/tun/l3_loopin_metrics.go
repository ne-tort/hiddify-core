package tun

import (
	"context"
	"fmt"
	"log"
	"sync/atomic"
	"time"

	cippump "github.com/sagernet/sing-box/transport/masque/connectip/pump"
)

// loopInMetricsSession wires LoopIn + host-kernel read observers when env metrics are enabled.
type loopInMetricsSession struct {
	loopObs      *cippump.LoopInObserver
	readObs      *HostKernelReadObserver
	bridge       *L3OverlayBridge
	wirePkts      atomic.Int64
	ingressPkts   atomic.Int64
	lastPkts      int64
	lastWirePkts  int64
	lastIngressPkts int64
	lastReadNanos int64
	lastFlowBytes uint64
	tickInterval time.Duration
	stopOnce     func()
}

func attachLoopInMetrics(bridge *L3OverlayBridge, device cippump.TunnelDevice) *loopInMetricsSession {
	if !cippump.LoopInMetricsEnabled() {
		return nil
	}
	s := &loopInMetricsSession{
		loopObs: &cippump.LoopInObserver{},
		readObs: &HostKernelReadObserver{},
		bridge:  bridge,
	}
	if bridge != nil {
		bridge.mu.Lock()
		kd := bridge.kernel
		bridge.mu.Unlock()
		if kd != nil {
			kd.AttachReadObserver(s.readObs)
		}
	}
	if kd, ok := device.(*KernelTunDevice); ok && s.readObs != nil {
		kd.AttachReadObserver(s.readObs)
	}
	log.Print("connect-ip LoopIn metrics: armed")
	return s
}

func (s *loopInMetricsSession) apply(opts *cippump.TunnelOptions) {
	if s == nil || opts == nil {
		return
	}
	opts.LoopInObserver = s.loopObs
}

func (s *loopInMetricsSession) wrapPacketConn(pc *NativePumpPacketConn) *NativePumpPacketConn {
	if s == nil || pc == nil {
		return pc
	}
	origRead := pc.Read
	pc.Read = func(ctx context.Context, buf []byte) (int, error) {
		n, err := origRead(ctx, buf)
		if n > 0 {
			s.ingressPkts.Add(1)
		}
		return n, err
	}
	origInPlace := pc.WriteInPlace
	pc.WriteInPlace = func(p []byte) (bool, []byte, error) {
		s.wirePkts.Add(1)
		return origInPlace(p)
	}
	origWrite := pc.Write
	pc.Write = func(p []byte) ([]byte, error) {
		s.wirePkts.Add(1)
		return origWrite(p)
	}
	return pc
}

func (s *loopInMetricsSession) startReporter(ctx context.Context) {
	if s == nil {
		return
	}
	interval := 2 * time.Second
	if cippump.LoopInMetricsEnabled() {
		interval = 500 * time.Millisecond
	}
	s.tickInterval = interval
	tick := time.NewTicker(interval)
	done := make(chan struct{})
	go func() {
		defer tick.Stop()
		for {
			select {
			case <-ctx.Done():
				s.logSnapshot()
				close(done)
				return
			case <-tick.C:
				s.logSnapshot()
			}
		}
	}()
	s.stopOnce = func() {
		<-done
	}
}

func (s *loopInMetricsSession) wait() {
	if s == nil || s.stopOnce == nil {
		return
	}
	s.stopOnce()
}

func (s *loopInMetricsSession) logSnapshot() {
	if s == nil || s.loopObs == nil {
		return
	}
	st := s.loopObs.Snapshot()
	delta := st.Pkts - s.lastPkts
	s.lastPkts = st.Pkts
	readDelta := st.ReadNanos - s.lastReadNanos
	s.lastReadNanos = st.ReadNanos
	wire := s.wirePkts.Load()
	wireDelta := wire - s.lastWirePkts
	s.lastWirePkts = wire
	ingress := s.ingressPkts.Load()
	ingressDelta := ingress - s.lastIngressPkts
	s.lastIngressPkts = ingress
	host := s.readObs.Snapshot()
	flowBytes := uint64(0)
	if s.bridge != nil {
		flowBytes = s.bridge.flowEgressBytes.Load()
	}
	line := cippump.FormatLoopInMetricsLine(st, host.Accepted, host.ReadUsPerPkt)
	line += fmt.Sprintf(" wire_pkts=%d host_zero=%d host_skipped=%d flow_egress_bytes=%d", wire, host.Zero, host.Skipped, flowBytes)
	if delta > 0 || wireDelta > 0 || ingressDelta > 0 {
		sec := 2.0
		if s.tickInterval > 0 {
			sec = s.tickInterval.Seconds()
		}
		intervalPPS := float64(loopInMetricsMax64(delta, wireDelta)) / sec
		line += fmt.Sprintf(" delta_pkts=%d delta_wire=%d interval_pps=%.0f ingress_pkts=%d", delta, wireDelta, intervalPPS, ingress)
		if ingressDelta > 0 {
			line += fmt.Sprintf(" delta_ingress=%d ingress_pps=%.0f", ingressDelta, float64(ingressDelta)/sec)
		}
		if delta > 0 && readDelta > 0 {
			line += fmt.Sprintf(" delta_read_us/pkt=%.1f", float64(readDelta)/float64(delta)/1000.0)
		}
		if flowDelta := int64(flowBytes) - int64(s.lastFlowBytes); flowDelta > 0 {
			line += fmt.Sprintf(" delta_flow_bytes=%d", flowDelta)
		}
	}
	s.lastFlowBytes = flowBytes
	log.Print(line)
}

func loopInMetricsMax64(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}
