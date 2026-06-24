package http2

import "testing"

func TestMasqueUploadEagerWindowDefaultOn(t *testing.T) {
	if !masqueUploadEagerWindowEnabled() {
		t.Fatal("expected upload eager window enabled by default")
	}
}

func TestMasqueUploadEagerWindowDisabled(t *testing.T) {
	t.Setenv(envH2UploadEagerWindow, "0")
	if masqueUploadEagerWindowEnabled() {
		t.Fatal("expected upload eager window disabled")
	}
}
