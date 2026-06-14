package h3

import "testing"

func TestH3BidiBootstrapUploadBytes(t *testing.T) {
	t.Setenv(envH2BidiBootstrapUpload, "4")
	if got := H3BidiBootstrapUploadBytes(); got != 4*1024 {
		t.Fatalf("got %d want %d", got, 4*1024)
	}
	t.Setenv(envH3BidiBootstrapUpload, "8")
	if got := H3BidiBootstrapUploadBytes(); got != 8*1024 {
		t.Fatalf("H3 override: got %d want %d", got, 8*1024)
	}
	t.Setenv(envH3BidiBootstrapUpload, "0")
	if got := H3BidiBootstrapUploadBytes(); got != 0 {
		t.Fatalf("disabled: got %d want 0", got)
	}
}
