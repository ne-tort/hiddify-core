package http2

import "io"

// masqueUploadWireAck is implemented by MASQUE H2 Extended CONNECT upload bodies.
type masqueUploadWireAck interface {
	MasqueUploadWireAck(n int)
}

func masqueAckUploadWireSent(body io.ReadCloser, n int) {
	if body == nil || n <= 0 {
		return
	}
	if a, ok := body.(masqueUploadWireAck); ok {
		a.MasqueUploadWireAck(n)
	}
}
