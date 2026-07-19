package connectip

import "github.com/quic-go/quic-go"

// h2DefaultMaxDatagramPayload is the max RFC 9297 DATAGRAM capsule payload (contextID||IP)
// accepted on H2 CONNECT-IP streams when no per-stream override is set.
// Matches transport/masque/connectip.H2MaxCapsulePayload(DefaultDatagramCeilingMax=1500).
const h2DefaultMaxDatagramPayload = 1500 + 80

// h2DatagramTooLarge returns a quic.DatagramTooLargeError when payload exceeds max so
// Conn.finishWritePacketSend can compose ICMP PTB (H3 parity; RFC 9484 §7.2.1).
// max<=0 uses h2DefaultMaxDatagramPayload.
func h2DatagramTooLarge(payloadLen, max int) error {
	if max <= 0 {
		max = h2DefaultMaxDatagramPayload
	}
	if payloadLen <= max {
		return nil
	}
	return &quic.DatagramTooLargeError{MaxDatagramPayloadSize: int64(max)}
}
