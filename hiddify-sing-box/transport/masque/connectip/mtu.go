package connectip

const (
	// DefaultDatagramCeilingMax is the default CONNECT-IP IPv4 datagram ceiling when endpoint mtu unset.
	// Soft-ceiling / PTB gate uses this IP size domain (not underlay capsule size).
	DefaultDatagramCeilingMax = 1500
	// MaxConfiguredDatagramCeiling is the inclusive upper bound from endpoint mtu in JSON (no env).
	MaxConfiguredDatagramCeiling = 9000
	// H3FramingSlack (FramingSlack) reserves QUIC/H3 HTTP DATAGRAM framing from the ceiling for
	// H3NetstackMTU and adds the same headroom for H2MaxCapsulePayload. Distinct from
	// TCPHTTP3DatagramSlack (WireSlack=128) used for practical H3 IPv4/MSS (MaxIPv4WireBytes).
	H3FramingSlack = 80
	// MaxIPv4WireBytes = DefaultDatagramCeilingMax − TCPHTTP3DatagramSlack (WireSlack).
	// Do not equate to H3NetstackMTU (ceiling − FramingSlack): 1372 ≠ 1420 by design (P2-10).
	MaxIPv4WireBytes = DefaultDatagramCeilingMax - TCPHTTP3DatagramSlack
)

// H3NetstackMTU returns gVisor link MTU for H3 overlay (ceiling minus FramingSlack).
func H3NetstackMTU(ceiling int) int {
	if ceiling < 1280 {
		return 1280
	}
	if ceiling <= H3FramingSlack+576 {
		return ceiling
	}
	return ceiling - H3FramingSlack
}

// H2NetstackMTU returns gVisor link MTU for H2 overlay (full ceiling, no slack subtraction).
func H2NetstackMTU(ceiling int) int {
	if ceiling < 1280 {
		return 1280
	}
	return ceiling
}

// H2MaxCapsulePayload returns max RFC 9297 DATAGRAM capsule body bytes for H2 (ceiling + FramingSlack).
func H2MaxCapsulePayload(ceilingMax int) int {
	return ceilingMax + H3FramingSlack
}

// MaxIPv4Datagram returns the forwarder max IPv4 datagram size (WireSlack band).
func MaxIPv4Datagram(ceilingMax int) int {
	if ceilingMax > 0 && ceilingMax < MaxIPv4WireBytes {
		return ceilingMax - H3FramingSlack
	}
	return MaxIPv4WireBytes
}
