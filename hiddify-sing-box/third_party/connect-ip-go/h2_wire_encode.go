package connectip

import (
	"bytes"

	"github.com/quic-go/quic-go/http3"
)

const h2PendingWireGrow = 64 * 1024

func appendHTTPDatagramCapsule(buf *bytes.Buffer, payload []byte) error {
	if buf != nil && buf.Cap() == 0 {
		buf.Grow(h2PendingWireGrow)
	}
	return http3.WriteCapsule(buf, capsuleTypeHTTPDatagram, payload)
}

func composeProxiedIPDatagramPayload(contextPrefix, ipPacket []byte) []byte {
	out := make([]byte, 0, len(contextPrefix)+len(ipPacket))
	out = append(out, contextPrefix...)
	out = append(out, ipPacket...)
	return out
}
