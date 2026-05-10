package masque

import "io"

// h2ExtendedConnectUploadBody wraps the client's upload io.PipeReader so net/http's HTTP/2
// transport does not close it from cleanupWriteRequest when the peer half-closes the response
// (END_STREAM). Without this, upload on the CONNECT stream can be torn down while the tunnel
// is still active. Same idea as connect-ip-go DialHTTP2 (h2ExtendedConnectDuplexBody).
type h2ExtendedConnectUploadBody struct {
	pipe *io.PipeReader
}

func (b *h2ExtendedConnectUploadBody) Read(p []byte) (int, error) {
	if b == nil || b.pipe == nil {
		return 0, io.ErrUnexpectedEOF
	}
	return b.pipe.Read(p)
}

func (*h2ExtendedConnectUploadBody) Close() error {
	return nil
}
