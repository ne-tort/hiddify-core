package masque

import (
	"context"
	"errors"
	"net/netip"
	"time"

	cip "github.com/sagernet/sing-box/transport/masque/connectip"
	ciptun "github.com/sagernet/sing-box/transport/masque/connectip/tun"
	"github.com/sagernet/sing-box/transport/masque/session"
	M "github.com/sagernet/sing/common/metadata"
)

// PlaneSession lifecycle (W-IP-ARCH-3):
// Closed → Open → Active (IngressLoop ‖ EgressBatch)
// → Draining (short TCP FIN/RST: flush only)
// → Stale (QUIC/stream fatal / server recycle latch)
// → Recycle (StopIngress → CloseDataplane → Open → Rebind → RestartIngress) → Active

// MarkConnectIPServerRecycled marks the CONNECT-IP plane stale after masque-server restart (W-IP-ARCH-3).
func (s *coreSession) MarkConnectIPServerRecycled() {
	s.connectIPServerRecycled.Store(true)
}

// ConnectIPServerGenerationStale reports an explicit server-recycle signal (W-IP-ARCH-3).
func (s *coreSession) ConnectIPServerGenerationStale() bool {
	return s.connectIPServerRecycled.Load()
}

// ConnectIPNativeL3Active reports whether tun L3 overlay owns the packet plane.
func (s *coreSession) ConnectIPNativeL3Active() bool {
	return s.connectIPNativeL3Active.Load()
}

// ClearConnectIPServerRecycled clears recycle latch after successful plane reopen.
func (s *coreSession) ClearConnectIPServerRecycled() {
	s.connectIPServerRecycled.Store(false)
}

// ResetConnectIPTCPAfterShortRelay drains egress/ACK wake after a short CM/tun relay (nc probe).
func (s *coreSession) ResetConnectIPTCPAfterShortRelay() {
	if s.connectIPNativeL3Active.Load() {
		return
	}
	s.Mu.Lock()
	ns := s.TCPNetstack
	if impl, ok := ns.(*cip.Netstack); ok && impl != nil {
		s.IngressTCPNetstack.Store(impl)
		s.maybeStartConnectIPIngressLocked()
	}
	s.Mu.Unlock()
	impl, ok := ns.(*cip.Netstack)
	if !ok || impl == nil {
		s.ClearConnectIPServerRecycled()
		s.ConnectIPTCPInstallInflight.Store(0)
		return
	}
	s.flushPreTCPNetstackIngress(impl)
	host := connectIPIngressHost{s: s}
	for i := 0; i < 64; i++ {
		host.IngressFlushAckWake()
		s.pokeConnectIPEgressSend()
		impl.ScheduleOutboundDrain()
		if impl.OutboundQueueDepth() == 0 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	s.ClearConnectIPServerRecycled()
	s.ConnectIPTCPInstallInflight.Store(0)
}

func (s *coreSession) noteConnectIPNativeL3IngressWake(pkt []byte) {
	s.ConnectIPIngressAckWake.NoteFromPacket(pkt)
}

func (s *coreSession) flushConnectIPNativeL3IngressAckWakeForce() {
	if !s.connectIPNativeL3Active.Load() {
		return
	}
	if reader := s.ipIngressPacketReader.Load(); reader != nil {
		reader.FlushEgressBatch()
	}
}

// FlushConnectIPNativeL3IngressAckWake completes one native L3 LoopOut iteration (IP-DP-1).
// Prod path: RunPump OnLoopOutEnd; retained for short-flow / legacy hooks.
func (s *coreSession) FlushConnectIPNativeL3IngressAckWake() {
	if !s.connectIPNativeL3Active.Load() {
		return
	}
	if s.ConnectIPIngressAckWake.TakePending() {
		s.flushConnectIPNativeL3IngressAckWakeForce()
	}
	if plane := s.connectIPNativeL3Plane.Load(); plane != nil {
		if bridge := plane.Bridge(); bridge != nil {
			bridge.ScheduleOutboundDrain()
		}
	}
}

// FlushConnectIPNativeL3AfterShortFlow drains egress/ACK wake after tun L3 short TCP (nc probe vs bulk).
func (s *coreSession) FlushConnectIPNativeL3AfterShortFlow(egressBytes uint64) {
	n := 2
	if egressBytes >= ciptun.L3BulkFlowEgressThreshold {
		n = 8
	}
	for i := 0; i < n; i++ {
		s.ConnectIPIngressAckWake.Schedule()
		s.flushConnectIPNativeL3IngressAckWakeForce()
	}
}

// ReopenConnectIPNativeL3Plane resets CONNECT-IP datagram state, rebinds tun L3 bridge, and restarts ingress.
func (s *coreSession) ReopenConnectIPNativeL3Plane(ctx context.Context) error {
	if !s.connectIPNativeL3Active.Load() {
		return nil
	}
	if !s.connectIPNativeL3Reopening.CompareAndSwap(false, true) {
		return nil
	}
	defer s.connectIPNativeL3Reopening.Store(false)

	plane := s.connectIPNativeL3Plane.Load()
	if plane != nil {
		plane.StopIngress()
	}

	s.Mu.Lock()
	host := s.ipPlaneHost()
	session.CloseConnectIPDataplaneLockedAssumeMu(&s.CoreSession, host)
	host.ResetIPH3TransportLockedAssumeMu()
	host.ResetH2UDPTransportLockedAssumeMu()
	s.Mu.Unlock()

	ipSess, err := s.OpenIPSession(ctx)
	if err != nil {
		return err
	}
	writer, reader, err := connectIPNativeL3PlaneEndpoints(ipSess)
	if err != nil {
		return err
	}
	if plane != nil {
		if bridge := plane.Bridge(); bridge != nil {
			bridge.RebindPacketPlane(writer, readPacketCtxAdapter{read: reader.ReadPacketWithContext})
		}
		if egress := s.connectIPNativeL3EgressSess.Load(); egress != nil {
			egress.IPPacketSession = ipSess
		}
		plane.RestartIngress()
	}
	s.ClearConnectIPServerRecycled()
	cip.EmitObservabilityEvent("connect_ip_native_l3_plane_recycled")
	return nil
}

// WaitConnectIPNativeL3PlaneReady blocks until native L3 ingress is active.
func (s *coreSession) WaitConnectIPNativeL3PlaneReady(ctx context.Context) error {
	if !s.connectIPNativeL3Active.Load() {
		return nil
	}
	plane := s.connectIPNativeL3Plane.Load()
	if plane == nil {
		return errors.New("connect-ip native l3 plane not wired")
	}
	if s.ipIngressPacketReader.Load() == nil {
		return errors.New("connect-ip packet reader not ready")
	}
	return plane.WaitReady(ctx)
}

// AfterNativeL3ShortTCP handles tun L3 FIN/RST: scoped flush only; Recycle when plane stale (§2.5).
func (s *coreSession) AfterNativeL3ShortTCP(ctx context.Context, dest netip.AddrPort, egressBytes uint64) {
	_ = dest
	s.FlushConnectIPNativeL3AfterShortFlow(egressBytes)
	if s.ConnectIPServerGenerationStale() {
		reopenCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		if err := s.ReopenConnectIPNativeL3Plane(reopenCtx); err != nil {
			return
		}
		if plane := s.connectIPNativeL3Plane.Load(); plane != nil {
			waitCtx, waitCancel := context.WithTimeout(ctx, 3*time.Second)
			_ = plane.WaitReady(waitCtx)
			waitCancel()
		}
	}
}

// noteConnectIPNativeL3IngressFatal logs pump loop exit; plane supervisor restarts (usque reconnect ADAPT).
// Server-recycle latch is only for explicit masque-server restart (W-IP-ARCH-3), not tun write backpressure.
func (s *coreSession) noteConnectIPNativeL3IngressFatal(err error) {
	if err == nil || errors.Is(err, context.Canceled) {
		return
	}
	if cip.IsBenignEgressTeardownError(err) {
		return
	}
	cip.EmitObservabilityEvent("connect_ip_native_l3_pump_fatal")
}

// WarmConnectIPTCPAfterShortRelay opens a brief TCP flow after nc probe so the next CM/tun
// bulk relay sees a live ingress/egress path (P0-03 synth parity with native preflight).
func (s *coreSession) WarmConnectIPTCPAfterShortRelay(ctx context.Context, dest M.Socksaddr) {
	if s.connectIPNativeL3Active.Load() {
		return
	}
	conn, err := s.dialConnectIPTCP(ctx, dest)
	if err != nil {
		return
	}
	buf := make([]byte, 4096)
	_ = conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	_, _ = conn.Read(buf)
	_ = conn.Close()
}
