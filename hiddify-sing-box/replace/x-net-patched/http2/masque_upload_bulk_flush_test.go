package http2



import (
	"io"
	"testing"
)



func TestMasqueUploadBulkFlushDefaultOn(t *testing.T) {

	t.Setenv(envH2UploadBulkFlush, "")

	if !masqueUploadBulkFlushEnabled() {

		t.Fatal("expected bulk upload flush enabled by default")

	}

	if masqueBulkFlushThreshold() != 256<<10 {
		t.Fatalf("expected default threshold 256KiB, got %d", masqueBulkFlushThreshold())
	}

}



func TestMasqueUploadBulkFlushDisabled(t *testing.T) {

	t.Setenv(envH2UploadBulkFlush, "0")

	if masqueUploadBulkFlushEnabled() {

		t.Fatal("expected bulk upload flush disabled")

	}

}



func TestMasqueBulkFlushThresholdEnv(t *testing.T) {

	t.Setenv(envH2UploadBulkFlushBytes, "65536")

	if got := masqueBulkFlushThreshold(); got != 65536 {

		t.Fatalf("threshold=%d want 65536", got)

	}

	if !masqueShouldBulkFlushNow(65536, false) {

		t.Fatal("expected flush at threshold")

	}

	if masqueShouldBulkFlushNow(32768, false) {

		t.Fatal("expected defer below threshold")

	}

}

type bulkFlushWireOnlyBody struct {
	acked int
}

func (b *bulkFlushWireOnlyBody) Read(p []byte) (int, error) { return 0, io.EOF }

func (b *bulkFlushWireOnlyBody) Close() error { return nil }

func (b *bulkFlushWireOnlyBody) MasqueUploadWireAck(n int) { b.acked += n }

type bulkFlushProbeBody struct {
	buffered  int
	consumed  int64
	acked     int
	bulkArmed bool
}

func (b *bulkFlushProbeBody) Read(p []byte) (int, error) { return 0, io.EOF }

func (b *bulkFlushProbeBody) Close() error { return nil }

func (b *bulkFlushProbeBody) MasqueUploadWireAck(n int) { b.acked += n }

func (b *bulkFlushProbeBody) MasqueUploadBuffered() int { return b.buffered }

func (b *bulkFlushProbeBody) UploadBootstrapPending() bool { return b.consumed > int64(b.acked) }

func (b *bulkFlushProbeBody) UploadBulkArmed() bool { return b.bulkArmed }

func TestMasqueShouldFlushBeforeBlockingRead(t *testing.T) {
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
	if masqueShouldFlushBeforeBlockingRead(body, 4096) {
		t.Fatal("expected no flush before blocking read after pipe fully flushed (bulk path)")
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


