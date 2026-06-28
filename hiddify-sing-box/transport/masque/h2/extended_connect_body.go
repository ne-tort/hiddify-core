package h2

import (
	"fmt"
	"io"
	"runtime"
	"sync/atomic"
	"time"
)

// ExtendedConnectUploadBody wraps the client's upload body reader so net/http's HTTP/2
// transport does not close it from cleanupWriteRequest when the peer half-closes the response
// (END_STREAM). Without this, upload on the CONNECT stream can be torn down while the tunnel
// is still active. Same idea as connect-ip-go DialHTTP2 (h2ExtendedConnectDuplexBody).
type ExtendedConnectUploadBody struct {
	Pipe     io.Reader
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

// MasqueUploadBuffered implements golang.org/x/net/http2 masqueUploadBuffered (upload pipe depth).
func (b *ExtendedConnectUploadBody) MasqueUploadBuffered() int {
	if b == nil || b.Pipe == nil {
		return 0
	}
	if u, ok := b.Pipe.(interface{ MasqueUploadBuffered() int }); ok {
		return u.MasqueUploadBuffered()
	}
	return -1
}

// MasqueUploadWireAck implements golang.org/x/net/http2 masqueUploadWireAck (post-Flush DATA ack).
func (b *ExtendedConnectUploadBody) MasqueUploadWireAck(n int) {
	if b != nil && n > 0 {
		b.wireSent.Add(int64(n))
	}
}

func (b *ExtendedConnectUploadBody) UploadWireSent() int64 {
	if b == nil {
		return 0
	}
	return b.wireSent.Load()
}

// AwaitUploadWireSent blocks until at least n TLS upload bytes are flushed (ConnectUploadWireAck).
func (b *ExtendedConnectUploadBody) AwaitUploadWireSent(n int64, timeout time.Duration) error {
	if b == nil || n <= 0 {
		return nil
	}
	deadline := time.Now().Add(timeout)
	spin := 0
	for {
		got := b.wireSent.Load()
		if got >= n || uploadWireTailSatisfied(got, n) {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("masque h2: upload wire barrier timeout (%d/%d bytes on wire)", got, n)
		}
		if spin < 128 {
			spin++
			runtime.Gosched()
			continue
		}
		time.Sleep(50 * time.Microsecond)
	}
}

// AwaitUploadConsumed blocks until http2 writeRequestBody has read at least n upload bytes from the pipe.
func (b *ExtendedConnectUploadBody) AwaitUploadConsumed(n int64, timeout time.Duration) error {
	if b == nil || n <= 0 {
		return nil
	}
	deadline := time.Now().Add(timeout)
	spin := 0
	for b.consumed.Load() < n {
		if time.Now().After(deadline) {
			return fmt.Errorf("masque h2: upload consume barrier timeout (%d/%d bytes consumed)", b.consumed.Load(), n)
		}
		if spin < 128 {
			spin++
			runtime.Gosched()
			continue
		}
		time.Sleep(50 * time.Microsecond)
	}
	return nil
}

func uploadWireTailSatisfied(got, need int64) bool {
	const tailSlack = int64(262144)
	return got+tailSlack >= need || (need > 0 && got*1000 >= need*995)
}

// UploadWireTailSatisfied reports whether flushed TLS bytes are close enough for bulk-upload drain.
func UploadWireTailSatisfied(got, need int64) bool {
	return uploadWireTailSatisfied(got, need)
}

func (*ExtendedConnectUploadBody) Close() error {
	return nil
}
