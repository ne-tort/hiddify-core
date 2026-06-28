package masque

import mcip "github.com/sagernet/sing-box/transport/masque/connectip"

// stopConnectIPNativeL3Dataplane tears down native L3 TUN overlay state (W-IP-PROD-2).
// Idempotent: safe from tun inbound Stop, coreSession.Close, and ResetHopTemplates.
// Order: StopIngress → bridge.Close → native netstack → clear pointers → leave L3 mode.
func (s *coreSession) stopConnectIPNativeL3Dataplane() {
	if s == nil {
		return
	}
	if !s.connectIPNativeL3Active.Load() && s.connectIPNativeL3Plane.Load() == nil {
		return
	}
	plane := s.connectIPNativeL3Plane.Swap(nil)
	if plane != nil {
		plane.StopIngress()
		if bridge := plane.Bridge(); bridge != nil {
			_ = bridge.Close()
		}
	}
	if ns := s.connectIPNativeL3Netstack.Swap(nil); ns != nil {
		_ = ns.Close()
	}
	s.connectIPNativeL3EgressSess.Store(nil)
	s.connectIPNativeL3Reopening.Store(false)
	s.connectIPNativeL3Active.Store(false)
	mcip.EmitObservabilityEvent("connect_ip_native_l3_stopped")
}
