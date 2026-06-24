package masque

import "sync/atomic"

// Process-wide CONNECT-UDP drop counters (prod client path stays at zero; ref proxy increments under masque_ref).

var (
	oversizedDatagramDropTotal            atomic.Uint64
	oversizedUDPPacketDropTotal           atomic.Uint64
	transientUDPSendDropTotal             atomic.Uint64
	transientUDPReadDropTotal             atomic.Uint64
	transientHTTPDatagramSendDropTotal    atomic.Uint64
	transientHTTPDatagramReceiveDropTotal atomic.Uint64
	oversizedHTTPDatagramSendDropTotal    atomic.Uint64
	unknownContextHTTPDatagramDropTotal   atomic.Uint64
	malformedHTTPDatagramDropTotal        atomic.Uint64
	transientUDPSendTailDropTotal         atomic.Uint64
)

// TransientUDPSendDropTotal returns C2S UDP egress drops after retry exhaustion (tests/ops).
func TransientUDPSendDropTotal() uint64 {
	return transientUDPSendDropTotal.Load()
}

// TransientUDPSendTailDropTotal returns batched tail drops on sustained send pressure (should stay 0).
func TransientUDPSendTailDropTotal() uint64 {
	return transientUDPSendTailDropTotal.Load()
}

// TransientHTTPDatagramSendDropTotal returns UDP→HTTP datagram send drops after retry exhaustion.
func TransientHTTPDatagramSendDropTotal() uint64 {
	return transientHTTPDatagramSendDropTotal.Load()
}

// TransientHTTPDatagramReceiveDropTotal returns HTTP datagram receive drops after retry exhaustion.
func TransientHTTPDatagramReceiveDropTotal() uint64 {
	return transientHTTPDatagramReceiveDropTotal.Load()
}

// TransientUDPReadDropTotal returns UDP ingress drops before HTTP encapsulation.
func TransientUDPReadDropTotal() uint64 {
	return transientUDPReadDropTotal.Load()
}

// OversizedHTTPDatagramSendDropTotal returns QUIC datagram size limit drops on send.
func OversizedHTTPDatagramSendDropTotal() uint64 {
	return oversizedHTTPDatagramSendDropTotal.Load()
}

// UnknownContextHTTPDatagramDropTotal returns unknown-context HTTP datagram drops.
func UnknownContextHTTPDatagramDropTotal() uint64 {
	return unknownContextHTTPDatagramDropTotal.Load()
}

// MalformedHTTPDatagramDropTotal returns malformed HTTP datagram drops.
func MalformedHTTPDatagramDropTotal() uint64 {
	return malformedHTTPDatagramDropTotal.Load()
}
