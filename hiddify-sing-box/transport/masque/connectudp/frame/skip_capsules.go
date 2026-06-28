package frame

import (
	"fmt"
	"io"

	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/quic-go/quicvarint"
)

const (
	// SkipCapsuleDatagramMaxPayload bounds RFC 9297 DATAGRAM (0x00) capsule bodies on skip paths.
	SkipCapsuleDatagramMaxPayload = 1500 + 128
	// SkipCapsuleNondatagramMaxPayload bounds non-DATAGRAM capsule bodies (RFC 9297 §4.2 silent discard).
	SkipCapsuleNondatagramMaxPayload = 65536
)

// SkipRequestStreamCapsules drains capsules on an Extended CONNECT request stream.
// Unknown capsule types are silently discarded per RFC 9297 §4.2; returns io.EOF at stream end.
func SkipRequestStreamCapsules(str quicvarint.Reader) error {
	const capsuleTypeDatagram = http3.CapsuleType(0)
	for {
		ct, err := quicvarint.Read(str)
		if err != nil {
			return err
		}
		length, err := quicvarint.Read(str)
		if err != nil {
			if err == io.EOF {
				return io.ErrUnexpectedEOF
			}
			return err
		}
		max := int64(SkipCapsuleNondatagramMaxPayload)
		if http3.CapsuleType(ct) == capsuleTypeDatagram {
			max = int64(SkipCapsuleDatagramMaxPayload)
		}
		if int64(length) > max {
			return fmt.Errorf("masque connect-udp skip-capsules: type=%d capsule exceeds %d bytes", ct, max)
		}
		if length == 0 {
			continue
		}
		n, err := io.Copy(io.Discard, io.LimitReader(str, int64(length)))
		if err != nil {
			return err
		}
		if n < int64(length) {
			return fmt.Errorf("masque connect-udp skip-capsules: type=%d truncated capsule body", ct)
		}
	}
}
