package h2

import "fmt"

// TransportRole identifies one of two isolated http2.Transport pools on coreSession.
// CONNECT-UDP/IP and CONNECT-stream must not share a pool: a saturated CONNECT-stream
// iperf run can exhaust connection-level flow control and starve the post-TCP UDP probe
// (bench §15.3a). Do not merge slots without documenting the regression risk.
type TransportRole int

const (
	// TransportUDP is H2UDPTransport — CONNECT-UDP and CONNECT-IP capsule overlays.
	TransportUDP TransportRole = iota
	// TransportConnectStream is H2ConnectStreamTransport — RFC 8441 TCP bidi tunnels.
	TransportConnectStream
)

// SeparateTransportRoles lists every H2 client pool role. Length must stay 2.
var SeparateTransportRoles = []TransportRole{TransportUDP, TransportConnectStream}

func (r TransportRole) String() string {
	switch r {
	case TransportUDP:
		return "udp"
	case TransportConnectStream:
		return "connect-stream"
	default:
		return fmt.Sprintf("transport-role(%d)", int(r))
	}
}

// SessionFieldName maps a role to the coreSession field that owns its http2.Transport cache.
func (r TransportRole) SessionFieldName() string {
	switch r {
	case TransportUDP:
		return "H2UDPTransport"
	case TransportConnectStream:
		return "H2ConnectStreamTransport"
	default:
		return ""
	}
}
