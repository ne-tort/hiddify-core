package http2

import "testing"

func TestMasqueUploadEagerWindowProdDefaultOn(t *testing.T) {
	// Outside TestMain mutation: verify setter/getter; prod var defaults true at init.
	prev := masqueUploadEagerWindowOn
	t.Cleanup(func() { masqueUploadEagerWindowOn = prev })

	SetMasqueUploadEagerWindowEnabled(true)
	if !masqueUploadEagerWindowEnabled() {
		t.Fatal("expected upload eager on after Set(true)")
	}
	SetMasqueUploadEagerWindowEnabled(false)
	if masqueUploadEagerWindowEnabled() {
		t.Fatal("expected upload eager off after Set(false)")
	}
}
