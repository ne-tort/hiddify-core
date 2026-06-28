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
	buffered int
	acked    int
}

func (b *bulkFlushProbeBody) Read(p []byte) (int, error) { return 0, io.EOF }

func (b *bulkFlushProbeBody) Close() error { return nil }

func (b *bulkFlushProbeBody) MasqueUploadWireAck(n int) { b.acked += n }

func (b *bulkFlushProbeBody) MasqueUploadBuffered() int { return b.buffered }

func TestMasqueShouldFlushBeforeBlockingRead(t *testing.T) {
	noBuf := &bulkFlushWireOnlyBody{}
	if masqueShouldFlushBeforeBlockingRead(noBuf, 4096) {
		t.Fatal("expected no flush without MasqueUploadBuffered")
	}
	body := &bulkFlushProbeBody{}
	body.buffered = 0
	if !masqueShouldFlushBeforeBlockingRead(body, 4096) {
		t.Fatal("expected flush when pipe empty with pending DATA")
	}
	body.buffered = 8192
	if masqueShouldFlushBeforeBlockingRead(body, 4096) {
		t.Fatal("expected no flush when more upload buffered")
	}
}


