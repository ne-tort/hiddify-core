package masque

import "sync/atomic"

var (
	masqueTCPDialTotal            atomic.Uint64
	masqueTCPDialFailTotal        atomic.Uint64
	masqueTCPFallbackTotal        atomic.Uint64
	masqueConnectIPStackReady     atomic.Uint64
	masqueConnectIPStackNotReady  atomic.Uint64
	masqueTCPErrorClassDial       atomic.Uint64
	masqueTCPErrorClassPolicy     atomic.Uint64
	masqueTCPErrorClassCapability atomic.Uint64
	masqueTCPErrorClassOther      atomic.Uint64
)

func recordTCPDialSuccess() {
	masqueTCPDialTotal.Add(1)
}

func recordTCPDialFailure() {
	masqueTCPDialFailTotal.Add(1)
}

func recordTCPFallback() {
	masqueTCPFallbackTotal.Add(1)
}

func recordConnectIPStackReady(ready bool) {
	if ready {
		masqueConnectIPStackReady.Add(1)
		return
	}
	masqueConnectIPStackNotReady.Add(1)
}

func recordTCPDialErrorClass(err error) {
	switch ClassifyError(err) {
	case ErrorClassDial:
		masqueTCPErrorClassDial.Add(1)
	case ErrorClassPolicy:
		masqueTCPErrorClassPolicy.Add(1)
	case ErrorClassCapability:
		masqueTCPErrorClassCapability.Add(1)
	default:
		masqueTCPErrorClassOther.Add(1)
	}
}

type MetricsSnapshot struct {
	TCPDialTotal             uint64 `json:"tcp_dial_total"`
	TCPDialFailTotal         uint64 `json:"tcp_dial_fail_total"`
	TCPFallbackTotal         uint64 `json:"tcp_fallback_total"`
	ConnectIPStackReady      uint64 `json:"connect_ip_stack_ready_total"`
	ConnectIPStackNotReady   uint64 `json:"connect_ip_stack_not_ready_total"`
	TCPErrorClassDialTotal   uint64 `json:"tcp_error_class_dial_total"`
	TCPErrorClassPolicyTotal uint64 `json:"tcp_error_class_policy_total"`
	TCPErrorClassCapTotal    uint64 `json:"tcp_error_class_capability_total"`
	TCPErrorClassOtherTotal  uint64 `json:"tcp_error_class_other_total"`
}

func SnapshotMetrics() MetricsSnapshot {
	return MetricsSnapshot{
		TCPDialTotal:             masqueTCPDialTotal.Load(),
		TCPDialFailTotal:         masqueTCPDialFailTotal.Load(),
		TCPFallbackTotal:         masqueTCPFallbackTotal.Load(),
		ConnectIPStackReady:      masqueConnectIPStackReady.Load(),
		ConnectIPStackNotReady:   masqueConnectIPStackNotReady.Load(),
		TCPErrorClassDialTotal:   masqueTCPErrorClassDial.Load(),
		TCPErrorClassPolicyTotal: masqueTCPErrorClassPolicy.Load(),
		TCPErrorClassCapTotal:    masqueTCPErrorClassCapability.Load(),
		TCPErrorClassOtherTotal:  masqueTCPErrorClassOther.Load(),
	}
}
