package connectip

import (
	"os"
	"strconv"
	"strings"
)

const (
	// DefaultDatagramCeilingMax is the inclusive upper bound for CONNECT-IP IPv4 datagram bytes.
	DefaultDatagramCeilingMax = 1500
	// DatagramSlack is QUIC/H3 HTTP DATAGRAM framing overhead reserved from the ceiling for gVisor link MTU.
	DatagramSlack = 80
)

// DatagramCeilingMax returns the configured CONNECT-IP datagram ceiling max.
// Override with HIDDIFY_MASQUE_DATAGRAM_CEILING_MAX in [1280, 65535]; invalid values fall back to DefaultDatagramCeilingMax.
func DatagramCeilingMax() int {
	raw := strings.TrimSpace(os.Getenv("HIDDIFY_MASQUE_DATAGRAM_CEILING_MAX"))
	if raw == "" {
		return DefaultDatagramCeilingMax
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n < 1280 || n > 65535 {
		return DefaultDatagramCeilingMax
	}
	return n
}

// H3NetstackMTU returns gVisor link MTU for H3 overlay (ceiling minus slack).
func H3NetstackMTU(ceiling int) int {
	if ceiling < 1280 {
		return 1280
	}
	if ceiling <= DatagramSlack+576 {
		return ceiling
	}
	return ceiling - DatagramSlack
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
	return ceilingMax + DatagramSlack
}

// MaxIPv4Datagram returns the forwarder max IPv4 datagram size (ceiling minus slack).
func MaxIPv4Datagram(ceilingMax int) int {
	return ceilingMax - DatagramSlack
}
