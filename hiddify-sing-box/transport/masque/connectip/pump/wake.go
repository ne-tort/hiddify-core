package pump

// OutboundDrainDevice extends TunnelDevice with post-ingress egress drain (CM netstack parity).
type OutboundDrainDevice interface {
	TunnelDevice
	ScheduleOutboundDrain()
}

// WakeHooks wires LoopOut end-of-iteration ACK / QUIC wake (R2 extension over usque).
type WakeHooks struct {
	// TakeIngressWakePending reports whether a deferred ingress ACK wake is pending.
	TakeIngressWakePending func() bool
	// PokeEgressTransport flushes QUIC/H2 datagram send (FlushEgressBatch analog).
	PokeEgressTransport func()
}

// FlushIngressAckWake runs one LoopOut iteration wake: optional transport poke + device egress drain.
func FlushIngressAckWake(device TunnelDevice, hooks WakeHooks) {
	if hooks.TakeIngressWakePending != nil && hooks.TakeIngressWakePending() {
		if hooks.PokeEgressTransport != nil {
			hooks.PokeEgressTransport()
		}
	}
	if d, ok := device.(OutboundDrainDevice); ok {
		d.ScheduleOutboundDrain()
	}
}
