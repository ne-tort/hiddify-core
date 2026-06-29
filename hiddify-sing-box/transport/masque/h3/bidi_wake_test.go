package h3

import "testing"

func TestH3BidiDownloadDrainEnabledProd(t *testing.T) {
	if !H3BidiDownloadDrainEnabled() {
		t.Fatal("expected H3 bidi download drain enabled (prod hardcoded)")
	}
}

func TestH3BidiWakeEnabledProd(t *testing.T) {
	c := &TunnelConn{}
	if !c.bidiUploadWakeEnabled() || !c.bidiDownloadDeliveryWakeEnabled() {
		t.Fatal("expected H3 bidi wake enabled (prod hardcoded)")
	}
}
