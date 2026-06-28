package netstack

// SetPumpLoopActive switches egress from async runExclusiveOutboundDrain to RunTunnel LoopIn.
func (s *Netstack) SetPumpLoopActive(on bool) {
	if s == nil {
		return
	}
	s.pumpLoopActive.Store(on)
	if on {
		s.outboundDraining.Store(false)
		s.outboundDrainPending.Store(false)
		s.signalEgressWake()
	}
}

func (s *Netstack) signalEgressWake() {
	if s == nil || s.egressWake == nil {
		return
	}
	select {
	case s.egressWake <- struct{}{}:
	default:
	}
}

// PumpTunnelDevice returns a RunTunnel LoopIn/LoopOut device for this netstack.
func (s *Netstack) PumpTunnelDevice() *DeviceAdapter {
	return NewDeviceAdapter(s)
}
