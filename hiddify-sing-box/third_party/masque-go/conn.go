package masque

import (
	"fmt"
	"io"
	"net"

	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/quic-go/quicvarint"
)

type masqueAddr struct{ string }

func (m masqueAddr) Network() string { return "connect-udp" }
func (m masqueAddr) String() string  { return m.string }

var _ net.Addr = masqueAddr{}

// tryDrainHTTPDatagrams exposes a non-blocking datagram dequeue when using quic-go's HTTP/3 implementation.
type tryDrainHTTPDatagrams interface {
	TryReceiveDatagram() ([]byte, bool)
}

// Bounds for draining ignored capsules on the HTTP/3 CONNECT-UDP request stream (skipCapsules).
const (
	skipCapsuleDatagramMaxPayload    = 1500 + 128
	skipCapsuleNondatagramMaxPayload = 65536
	capsuleTypeDatagram              = http3.CapsuleType(0)
)

func skipCapsules(str quicvarint.Reader) error {
	for {
		ct, r, err := http3.ParseCapsule(str)
		if err != nil {
			return err
		}
		max := int64(skipCapsuleNondatagramMaxPayload)
		if ct == capsuleTypeDatagram {
			max = int64(skipCapsuleDatagramMaxPayload)
		}
		n, err := io.Copy(io.Discard, io.LimitReader(r, max+1))
		if err != nil {
			return err
		}
		if n > max {
			return fmt.Errorf("masque connect-udp h3 skip-capsules: type=%d capsule exceeds %d bytes", ct, max)
		}
	}
}
