package http2

import (
	"io"
	"testing"
	"time"
)

type flushPolicyBody struct {
	buf       int
	bulkArmed bool
	bootstrap bool
	wireAck   bool
}

func (b *flushPolicyBody) Read([]byte) (int, error)     { return 0, io.EOF }
func (b *flushPolicyBody) Close() error                 { return nil }
func (b *flushPolicyBody) MasqueUploadWireAck(int)      {}
func (b *flushPolicyBody) MasqueUploadBuffered() int    { return b.buf }
func (b *flushPolicyBody) UploadBootstrapPending() bool { return b.bootstrap }
func (b *flushPolicyBody) UploadBulkArmed() bool        { return b.bulkArmed }

func TestMasqueFlushBeforeBlockingReadEmptyPipeAlwaysFlushes(t *testing.T) {
	// Pending must hit the wire before blocking Read — else bw holds forever.
	body := &flushPolicyBody{buf: 0, bulkArmed: true}
	if !masqueShouldFlushBeforeBlockingRead(body, 8<<10) {
		t.Fatal("empty pipe must Flush any pending before blocking Read")
	}
}

func TestMasqueBulkFlushDeadlineHonorsMinPending(t *testing.T) {
	at := time.Now().Add(-10 * time.Millisecond)
	if masqueShouldBulkFlushDeadline(8<<10, at, 0) {
		t.Fatal("deadline must not fire below MinPending")
	}
	if !masqueShouldBulkFlushDeadline(masqueBulkFlushMinPending, at, 0) {
		t.Fatal("deadline must fire at MinPending after MaxDelay")
	}
}

func TestMasqueUploadNeedsDownloadWakeIdleSkip(t *testing.T) {
	idle := &flushPolicyBody{buf: 0, bootstrap: false}
	if masqueUploadNeedsDownloadWake(idle) {
		t.Fatal("idle CONNECT-stream upload must not wake on download Read")
	}
	busy := &flushPolicyBody{buf: 4096}
	if !masqueUploadNeedsDownloadWake(busy) {
		t.Fatal("buffered upload must wake")
	}
}
