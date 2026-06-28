package http2

import "io"

// masqueUploadWireAck is implemented by MASQUE H2 Extended CONNECT upload bodies.
type masqueUploadWireAck interface {
	MasqueUploadWireAck(n int)
}

// masqueUploadBuffered reports upload pipe depth; 0 means writeRequestBody may block on Read.
type masqueUploadBuffered interface {
	masqueUploadWireAck
	MasqueUploadBuffered() int
}

// masqueShouldFlushBeforeBlockingRead flushes sub-threshold DATA before a blocking body.Read
// (H2 bidi bootstrap upload must reach the wire before download can start).
func masqueShouldFlushBeforeBlockingRead(body io.ReadCloser, pendingAck int) bool {
	if pendingAck <= 0 {
		return false
	}
	b, ok := body.(masqueUploadBuffered)
	if !ok {
		return false
	}
	switch buf := b.MasqueUploadBuffered(); {
	case buf < 0:
		return false
	case buf == 0:
		return true
	default:
		return false
	}
}

func masqueAckUploadWireSent(body io.ReadCloser, n int) {
	if body == nil || n <= 0 {
		return
	}
	if a, ok := body.(masqueUploadWireAck); ok {
		a.MasqueUploadWireAck(n)
	}
}
