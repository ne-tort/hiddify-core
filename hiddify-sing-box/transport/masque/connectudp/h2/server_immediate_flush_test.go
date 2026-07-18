package h2

import (
	"net/http/httptest"
	"testing"
)

// TestImmediateWriteFlushesFountainPending covers AUDIT A4 / TASKS F2.2:
// ICMP/immediate must not Reset pending wire without sending it.
func TestImmediateWriteFlushesFountainPending(t *testing.T) {
	rr := httptest.NewRecorder()
	w := newH2DownlinkWriter(rr, LegProfileDownloadFountain)

	payload := []byte("fountain-pkt")
	if err := w.AppendUDPPayloadAsCapsules(payload); err != nil {
		t.Fatal(err)
	}
	pendingLen := w.pendingWire.Len()
	if pendingLen == 0 {
		t.Fatal("expected pending after Append below flush threshold")
	}

	// Immediate ICMP (nil) must flush pending, not drop it.
	if err := w.WriteUDPPayloadAsCapsules(nil); err != nil {
		t.Fatal(err)
	}
	if w.pendingWire.Len() != 0 {
		t.Fatalf("pending left after immediate: %d", w.pendingWire.Len())
	}
	got := rr.Body.Len()
	if got < pendingLen {
		t.Fatalf("flushed body %d < pending %d — pending dropped (A4)", got, pendingLen)
	}
}
