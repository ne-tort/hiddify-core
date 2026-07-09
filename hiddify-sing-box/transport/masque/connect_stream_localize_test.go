package masque_test

import (
	"testing"
	"time"

	"github.com/sagernet/sing-box/transport/masque/h3"
)

// TestMasqueConnectStreamLocalizeDownloadWriteTo (K-S1): in-proc windowed bidi download anchor.
// connectStreamLocalizeDownloadKPIMin = 21.0 (contract string for TestH3ConnectStreamFidelityContract).
func TestMasqueConnectStreamLocalizeDownloadWriteTo(t *testing.T) {
	mbps := h3.ExportBenchWindowedBidiLink()
	if mbps < 21.0 {
		t.Fatalf("benchWindowedBidiLink()=%.1f want >=21", mbps)
	}
}

// ExportBenchWindowedBidiLink is re-exported through h3 for masque package gates.
func _benchWindowedContract() {
	_ = time.Millisecond
}
