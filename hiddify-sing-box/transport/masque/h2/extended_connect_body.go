package h2

import "io"

// ExtendedConnectUploadBody wraps the client's upload io.PipeReader so net/http's HTTP/2
// transport does not close it from cleanupWriteRequest when the peer half-closes the response
// (END_STREAM). Without this, upload on the CONNECT stream can be torn down while the tunnel
// is still active. Same idea as connect-ip-go DialHTTP2 (h2ExtendedConnectDuplexBody).
type ExtendedConnectUploadBody struct {
	Pipe *io.PipeReader
}

func (b *ExtendedConnectUploadBody) Read(p []byte) (int, error) {
	if b == nil || b.Pipe == nil {
		return 0, io.ErrUnexpectedEOF
	}
	return b.Pipe.Read(p)
}

func (*ExtendedConnectUploadBody) Close() error {
	return nil
}
