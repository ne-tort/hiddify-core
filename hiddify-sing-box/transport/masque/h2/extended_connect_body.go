package h2

import (
	"fmt"
	"io"
	"sync/atomic"
	"time"
)

// ExtendedConnectUploadBody wraps the client's upload io.PipeReader so net/http's HTTP/2
// transport does not close it from cleanupWriteRequest when the peer half-closes the response
// (END_STREAM). Without this, upload on the CONNECT stream can be torn down while the tunnel
// is still active. Same idea as connect-ip-go DialHTTP2 (h2ExtendedConnectDuplexBody).
type ExtendedConnectUploadBody struct {
	Pipe     *io.PipeReader
	consumed atomic.Int64
	wireSent atomic.Int64
}

func (b *ExtendedConnectUploadBody) Read(p []byte) (int, error) {
	if b == nil || b.Pipe == nil {
		return 0, io.ErrUnexpectedEOF
	}
	n, err := b.Pipe.Read(p)
	if n > 0 {
		b.consumed.Add(int64(n))
	}
	return n, err
}

// MasqueUploadWireAck implements golang.org/x/net/http2 masqueUploadWireAck (post-Flush DATA ack).
func (b *ExtendedConnectUploadBody) MasqueUploadWireAck(n int) {
	if b != nil && n > 0 {
		b.wireSent.Add(int64(n))
	}
}

// AwaitUploadConsumed blocks until http2 writeRequestBody has flushed at least n upload bytes.
func (b *ExtendedConnectUploadBody) AwaitUploadConsumed(n int64, timeout time.Duration) error {
	if b == nil || n <= 0 {
		return nil
	}
	deadline := time.Now().Add(timeout)
	for b.wireSent.Load() < n {
		if time.Now().After(deadline) {
			return fmt.Errorf("masque h2: upload wire barrier timeout (%d/%d bytes on wire)", b.wireSent.Load(), n)
		}
		time.Sleep(time.Millisecond)
	}
	return nil
}

func (*ExtendedConnectUploadBody) Close() error {
	return nil
}
