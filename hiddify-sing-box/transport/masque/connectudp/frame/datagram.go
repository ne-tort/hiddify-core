package frame

import (
	"errors"
	"fmt"
	"io"
)

const (
	// MaxProxiedUDPPayloadBytes is the RFC 9298 §5 maximum UDP proxying payload (Context ID 0).
	MaxProxiedUDPPayloadBytes = 65527
)

// ContextIDZeroWire is the RFC 9297 HTTP Datagram Context ID 0 prefix (QUIC varint 0x00).
var ContextIDZeroWire = []byte{0}

// ErrProxiedUDPPayloadTooLarge is returned when a proxied UDP payload exceeds RFC 9298 §5
// or a product CONNECT-UDP datagram size limit.
var ErrProxiedUDPPayloadTooLarge = errors.New("connect-udp: proxied UDP payload exceeds RFC 9298 maximum (65527 bytes)")

// ValidateProxiedUDPPayloadLen rejects single-datagram UDP payloads longer than RFC 9298 allows.
func ValidateProxiedUDPPayloadLen(n int) error {
	if n > MaxProxiedUDPPayloadBytes {
		return fmt.Errorf("%w: got %d", ErrProxiedUDPPayloadTooLarge, n)
	}
	return nil
}

// CheckConnectUDPUDPPayload enforces RFC 9298 §5 (≤65527) and an optional product max
// (e.g. H2 MaxUDPPayloadPerDatagramCapsule). productMax<=0 means RFC-only.
// Empty payloads (n<=0) are allowed (ICMP / empty ctx0 soft-signal).
func CheckConnectUDPUDPPayload(n, productMax int) error {
	if n <= 0 {
		return nil
	}
	if err := ValidateProxiedUDPPayloadLen(n); err != nil {
		return err
	}
	if productMax > 0 && n > productMax {
		return fmt.Errorf("%w: got %d (product max %d)", ErrProxiedUDPPayloadTooLarge, n, productMax)
	}
	return nil
}

// ParseHTTPDatagramUDPFast extracts Context ID 0 payload on the hot path, falling back to ParseHTTPDatagramUDP.
func ParseHTTPDatagramUDPFast(data []byte) (payload []byte, ok bool, err error) {
	if len(data) == 0 {
		return nil, false, io.EOF
	}
	if data[0] == 0 {
		return data[1:], true, nil
	}
	return ParseHTTPDatagramUDP(data)
}

// ParseHTTPDatagramUDP interprets CONNECT-UDP HTTP Datagram payload (RFC 9297 / MASQUE).
// Return convention matches masque-go parseProxiedDatagramPayload for H3 parity:
// truncated / empty structural cases use io.EOF; callers drop (do not treat as capsule mis-framing).
func ParseHTTPDatagramUDP(data []byte) (payload []byte, ok bool, err error) {
	if len(data) == 0 {
		return nil, false, io.EOF
	}
	if data[0] == 0 {
		return data[1:], true, nil
	}
	if data[0]&0xc0 == 0 {
		return nil, false, nil
	}
	if data[0]&0x3f != 0 {
		return nil, false, nil
	}
	switch data[0] >> 6 {
	case 1:
		if len(data) < 2 {
			return nil, false, io.EOF
		}
		if data[1] == 0 {
			return data[2:], true, nil
		}
		return nil, false, nil
	case 2:
		if len(data) < 4 {
			return nil, false, io.EOF
		}
		if data[1] == 0 && data[2] == 0 && data[3] == 0 {
			return data[4:], true, nil
		}
		return nil, false, nil
	case 3:
		if len(data) < 8 {
			return nil, false, io.EOF
		}
		if data[1] == 0 && data[2] == 0 && data[3] == 0 && data[4] == 0 && data[5] == 0 && data[6] == 0 && data[7] == 0 {
			return data[8:], true, nil
		}
		return nil, false, nil
	}
	return nil, false, io.EOF
}
