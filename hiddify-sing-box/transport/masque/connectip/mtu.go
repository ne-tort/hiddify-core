package connectip

const (
	// DefaultDatagramCeilingMax is the inclusive upper bound for CONNECT-IP IPv4 datagram bytes.
	// Per-endpoint mtu in masque config overrides session ceiling at runtime.
	DefaultDatagramCeilingMax = 1500
	// H3FramingSlack is QUIC/H3 HTTP DATAGRAM framing overhead reserved from the ceiling for gVisor link MTU.
	H3FramingSlack = 80
	// MaxIPv4WireBytes caps CONNECT-IP IPv4 datagram size on the H3 return path (~1372 B practical wire limit).
	MaxIPv4WireBytes = 1372
)

// H3NetstackMTU returns gVisor link MTU for H3 overlay (ceiling minus slack).
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

// H2MaxCapsulePayload returns max RFC 9297 DATAGRAM capsule body bytes for H2 (ceiling + slack).
func H2MaxCapsulePayload(ceilingMax int) int {
	return ceilingMax + H3FramingSlack
}

// MaxIPv4Datagram returns the forwarder max IPv4 datagram size (H3 wire limit).
func MaxIPv4Datagram(ceilingMax int) int {
	if ceilingMax > 0 && ceilingMax < MaxIPv4WireBytes {
		return ceilingMax - H3FramingSlack
	}
	return MaxIPv4WireBytes
}
