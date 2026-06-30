package h3

import "testing"

func TestH3BidiBootstrapUploadBytesProdConstant(t *testing.T) {
	t.Setenv("MASQUE_H3_BIDI_BOOTSTRAP_UPLOAD_BYTES", "8")
	t.Setenv("MASQUE_H2_BIDI_BOOTSTRAP_UPLOAD_BYTES", "4")
	if H3BidiBootstrapUploadBytes != 4*1024 {
		t.Fatalf("prod constant ignores env: got %d want %d", H3BidiBootstrapUploadBytes, 4*1024)
	}
}
