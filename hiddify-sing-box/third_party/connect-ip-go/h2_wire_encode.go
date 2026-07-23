package connectip

import (
	"bytes"

	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/quic-go/quicvarint"
)

const h2PendingWireGrow = 64 * 1024

func appendHTTPDatagramCapsule(buf *bytes.Buffer, payload []byte) error {
	if buf != nil && buf.Cap() == 0 {
		buf.Grow(h2PendingWireGrow)
	}
	return http3.WriteCapsule(buf, capsuleTypeHTTPDatagram, payload)
}

// appendHTTPDatagramCapsuleParts writes RFC9297 DATAGRAM capsule without a middle payload alloc.
// hdrScratch is optional reusable storage for type+length varints (may be nil).
func appendHTTPDatagramCapsuleParts(buf *bytes.Buffer, hdrScratch *[]byte, parts ...[]byte) error {
	if buf != nil && buf.Cap() == 0 {
		buf.Grow(h2PendingWireGrow)
	}
	n := 0
	for _, p := range parts {
		n += len(p)
	}
	var hdr []byte
	if hdrScratch != nil {
		*hdrScratch = (*hdrScratch)[:0]
		if cap(*hdrScratch) < 16 {
			*hdrScratch = make([]byte, 0, 16)
		}
		*hdrScratch = quicvarint.Append(*hdrScratch, uint64(capsuleTypeHTTPDatagram))
		*hdrScratch = quicvarint.Append(*hdrScratch, uint64(n))
		hdr = *hdrScratch
	} else {
		hdr = quicvarint.Append(nil, uint64(capsuleTypeHTTPDatagram))
		hdr = quicvarint.Append(hdr, uint64(n))
	}
	if _, err := buf.Write(hdr); err != nil {
		return err
	}
	for _, p := range parts {
		if _, err := buf.Write(p); err != nil {
			return err
		}
	}
	return nil
}

func composeProxiedIPDatagramPayload(contextPrefix, ipPacket []byte) []byte {
	out := make([]byte, 0, len(contextPrefix)+len(ipPacket))
	out = append(out, contextPrefix...)
	out = append(out, ipPacket...)
	return out
}
