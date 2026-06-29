package stream

import "testing"

func TestH2BidiDownloadDrainEnabledProd(t *testing.T) {
	if !H2BidiDownloadDrainEnabled() {
		t.Fatal("expected H2 bidi download drain enabled (prod hardcoded)")
	}
}
