package http2



import "testing"



func TestMasqueUploadBulkFlushDefaultOn(t *testing.T) {

	t.Setenv(envH2UploadBulkFlush, "")

	if !masqueUploadBulkFlushEnabled() {

		t.Fatal("expected bulk upload flush enabled by default")

	}

	if masqueBulkFlushThreshold() != 64<<10 {
		t.Fatalf("expected default threshold 64KiB, got %d", masqueBulkFlushThreshold())
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


