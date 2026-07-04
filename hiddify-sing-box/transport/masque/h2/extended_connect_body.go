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
	Pipe   io.Reader
	Writer ConnectUploadPipeWriter
	consumed  atomic.Int64
	wireSent  atomic.Int64
	bulkArmed atomic.Bool
	// writerLive: Invisv/connect-ip-go — http2 END_STREAM follows PacketConn lifecycle, not pipe EOF flakes.
	writerLive atomic.Bool
}

// BeginUploadWriterLive marks the upload leg open until MarkUploadWriterDone (dial-time).
func (b *ExtendedConnectUploadBody) BeginUploadWriterLive() {
	if b != nil {
		b.writerLive.Store(true)
	}
}

// MasqueConnectStreamBidiUpload reports CONNECT-stream sustained upload pump (not UDP/IP asymmetric).
func (b *ExtendedConnectUploadBody) MasqueConnectStreamBidiUpload() bool {
	return b != nil && !b.writerLive.Load()
}

// MasqueUploadPipeWriterOpen reports whether the client upload pipe writer is still open.
func (b *ExtendedConnectUploadBody) MasqueUploadPipeWriterOpen() bool {
	if b == nil {
		return false
	}
	if b.Writer != nil {
		return b.Writer.MasqueUploadWriterOpen()
	}
	if b.Pipe == nil {
		return false
	}
	if w, ok := b.Pipe.(interface{ MasqueUploadWriterOpen() bool }); ok {
		return w.MasqueUploadWriterOpen()
	}
	return false
}

// MarkUploadWriterDone signals http2 to half-close the CONNECT upload stream (PacketConn.Close).
func (b *ExtendedConnectUploadBody) MarkUploadWriterDone() {
	if b != nil {
		b.writerLive.Store(false)
	}
}

// uploadBulkArmConsumedMin: arm bulk TLS batching after first real UDP payload (not Prime empty capsule).
const uploadBulkArmConsumedMin = 512

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

// MasqueUploadWriterOpen reports whether the client upload pipe writer is still open.
// Only true after BeginUploadWriterLive (CONNECT-UDP / CONNECT-IP asymmetric leg).
// CONNECT-stream must return false so x/net stays on the standard bidi writeRequest path.
func (b *ExtendedConnectUploadBody) MasqueUploadWriterOpen() bool {
	if b == nil || !b.writerLive.Load() {
		return false
	}
	if b.Writer != nil {
		return b.Writer.MasqueUploadWriterOpen()
	}
	if b.Pipe == nil {
		return false
	}
	if w, ok := b.Pipe.(interface{ MasqueUploadWriterOpen() bool }); ok {
		return w.MasqueUploadWriterOpen()
	}
	return false
}

// MasqueUploadBuffered implements golang.org/x/net/http2 masqueUploadBuffered (upload pipe depth).
func (b *ExtendedConnectUploadBody) MasqueUploadBuffered() int {
	if b == nil || b.Pipe == nil {
		return 0
	}
	if u, ok := b.Pipe.(interface{ MasqueUploadBuffered() int }); ok {
		return u.MasqueUploadBuffered()
	}
	return 0
}

// UploadPipeCap implements golang.org/x/net/http2 masqueUploadPipeCap for shallow upload pipes.
func (b *ExtendedConnectUploadBody) UploadPipeCap() int {
	if b == nil || b.Pipe == nil {
		return 0
	}
	if u, ok := b.Pipe.(interface{ UploadPipeCap() int }); ok {
		return u.UploadPipeCap()
	}
	return 0
}

// SetMasqueUploadFlowWake forwards flow-control wake to the shallow upload pipe reader.
func (b *ExtendedConnectUploadBody) SetMasqueUploadFlowWake(fn func()) {
	if b == nil || b.Pipe == nil {
		return
	}
	if t, ok := b.Pipe.(interface{ SetMasqueUploadFlowWake(func()) }); ok {
		t.SetMasqueUploadFlowWake(fn)
	}
}

// MasqueWakeRequestBodyWrite nudges http2 writeRequestBody out of awaitFlowControl (bidi download read).
func (b *ExtendedConnectUploadBody) MasqueWakeRequestBodyWrite() {
	if b == nil {
		return
	}
	if b.Writer != nil {
		if p, ok := b.Writer.(interface{ PokeH2BidiDownload() }); ok {
			p.PokeH2BidiDownload()
			return
		}
	}
	if b.Pipe != nil {
		if w, ok := b.Pipe.(interface{ MasqueWakeUploadFlow() }); ok {
			w.MasqueWakeUploadFlow()
		}
	}
}

// MasqueUploadWireAck implements golang.org/x/net/http2 masqueUploadWireAck (post-Flush DATA ack).
func (b *ExtendedConnectUploadBody) MasqueUploadWireAck(n int) {
	if b != nil && n > 0 {
		b.wireSent.Add(int64(n))
		if b.consumed.Load() >= uploadBulkArmConsumedMin {
			b.bulkArmed.Store(true)
		}
	}
}

func (b *ExtendedConnectUploadBody) UploadWireSent() int64 {
	if b == nil {
		return 0
	}
	return b.wireSent.Load()
}

// UploadBootstrapPending reports unconsumed-on-wire pipe bytes (Invisv bootstrap discriminator).
func (b *ExtendedConnectUploadBody) UploadBootstrapPending() bool {
	if b == nil {
		return false
	}
	return b.consumed.Load() > b.wireSent.Load()
}

// UploadBulkArmed reports sustained upload (bulk TLS flush owns pacing after first user payload).
func (b *ExtendedConnectUploadBody) UploadBulkArmed() bool {
	if b == nil {
		return false
	}
	return b.bulkArmed.Load()
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
