package http2

import (
	"io"
	"testing"
	"time"
)

func TestMasqueUploadBulkFlushThresholdBaked(t *testing.T) {
	t.Parallel()
	if masqueBulkFlushThresholdBytes != 256<<10 {
		t.Fatalf("threshold=%d want 256KiB", masqueBulkFlushThresholdBytes)
	}
	if !masqueShouldBulkFlushNow(256<<10, false) {
		t.Fatal("expected flush at threshold")
	}
	if masqueShouldBulkFlushNow(32<<10, false) {
		t.Fatal("expected defer below threshold")
	}
	if !masqueShouldBulkFlushNow(1, true) {
		t.Fatal("expected flush on EOF with pending")
	}
	if !masqueShouldBulkFlushDeadline(64<<10, time.Now().Add(-masqueBulkFlushMaxDelay)) {
		t.Fatal("expected flush after max delay")
	}
}

type bulkFlushWireOnlyBody struct {
	acked int
}

func (b *bulkFlushWireOnlyBody) Read(p []byte) (int, error) { return 0, io.EOF }
func (b *bulkFlushWireOnlyBody) Close() error              { return nil }
func (b *bulkFlushWireOnlyBody) MasqueUploadWireAck(n int) { b.acked += n }

type bulkFlushProbeBody struct {
	buffered  int
	consumed  int64
	acked     int
	bulkArmed bool
}

func (b *bulkFlushProbeBody) Read(p []byte) (int, error) { return 0, io.EOF }
func (b *bulkFlushProbeBody) Close() error              { return nil }
func (b *bulkFlushProbeBody) MasqueUploadWireAck(n int) { b.acked += n }
func (b *bulkFlushProbeBody) MasqueUploadBuffered() int { return b.buffered }
func (b *bulkFlushProbeBody) UploadBootstrapPending() bool {
	return b.consumed > int64(b.acked)
}
func (b *bulkFlushProbeBody) UploadBulkArmed() bool { return b.bulkArmed }

func TestMasqueShouldFlushBeforeBlockingRead(t *testing.T) {
	t.Parallel()
	noBuf := &bulkFlushWireOnlyBody{}
	if masqueShouldFlushBeforeBlockingRead(noBuf, 4096) {
		t.Fatal("expected no flush without MasqueUploadBuffered")
	}
	body := &bulkFlushProbeBody{consumed: 4096}
	body.buffered = 0
	if !masqueShouldFlushBeforeBlockingRead(body, 4096) {
		t.Fatal("expected flush when bootstrap pending with pipe buf=0")
	}
	body.acked = 4096
	// CONNECT-stream (no writer-live): still flush pending DATA when the pipe is empty
	// before a blocking Read — otherwise bidi stalls under FC (H2-W5 / W1 adjacency).
	if !masqueShouldFlushBeforeBlockingRead(body, 4096) {
		t.Fatal("expected flush when CONNECT-stream pipe empty with pendingAck")
	}
	body.bulkArmed = true
	body.consumed = 8192
	body.acked = 4096
	if masqueShouldInteractiveUploadFlush(body, 4096) {
		t.Fatal("expected no interactive flush when bulk armed")
	}
	body.bulkArmed = false
	body.buffered = 8192
	body.consumed = 8192
	body.acked = 0
	if masqueShouldFlushBeforeBlockingRead(body, 4096) {
		t.Fatal("expected no flush when pipe lightly buffered")
	}
	body.buffered = masqueUploadPipeFlushWaterMark
	if !masqueShouldFlushBeforeBlockingRead(body, 4096) {
		t.Fatal("expected flush at upload pipe high watermark")
	}
	body.buffered = masqueUploadPipeFlushWaterMark - 1
	if masqueShouldFlushBeforeBlockingRead(body, 4096) {
		t.Fatal("expected no flush below upload pipe watermark")
	}
}

func TestMasqueShouldBootstrapUploadFlush(t *testing.T) {
	t.Parallel()
	body := &bulkFlushProbeBody{consumed: 1024}
	if !masqueShouldBootstrapUploadFlush(body, 1024) {
		t.Fatal("expected bootstrap flush when consumed ahead of wire")
	}
	body.acked = 1024
	if masqueShouldBootstrapUploadFlush(body, 1024) {
		t.Fatal("expected no bootstrap flush when pipe caught up on wire")
	}
	body.bulkArmed = true
	body.consumed = 2048
	body.acked = 1024
	if masqueShouldBootstrapUploadFlush(body, 1024) {
		t.Fatal("expected no bootstrap flush when bulk armed")
	}
}

func TestMasqueUploadBodyUsesBulkFlush(t *testing.T) {
	t.Parallel()
	if !masqueUploadBodyUsesBulkFlush(&bulkFlushWireOnlyBody{}) {
		t.Fatal("wire-ack body without shallow cap should use bulk flush")
	}
}
