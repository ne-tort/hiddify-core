package h2

import (
	_ "embed"
	"strings"
	"testing"
)

//go:embed packet_conn.go
var connectUDPH2PacketConnSource string

//go:embed packet_conn_upload.go
var connectUDPH2PacketConnUploadSource string

// TestConnectUDPH2BidiWriteContract locks thin sync bidi: immediate Write, no flush-under-lock.
func TestConnectUDPH2BidiWriteContract(t *testing.T) {
	t.Parallel()
	for _, sub := range []string{
		`writeUploadUDPPayloadUnlocked`,
		`takeUploadPendingLocked`,
		`writeUploadWireUnlocked`,
	} {
		if !strings.Contains(connectUDPH2PacketConnUploadSource, sub) && !strings.Contains(connectUDPH2PacketConnSource, sub) {
			t.Fatalf("H2 bidi write: missing %q", sub)
		}
	}
	if !strings.Contains(connectUDPH2PacketConnSource, `writeUploadUDPPayloadUnlocked`) {
		t.Fatal("packet_conn.go: bidi path must use immediate writeUploadUDPPayloadUnlocked")
	}
	if strings.Contains(connectUDPH2PacketConnSource, "uploadOnly") {
		t.Fatal("packet_conn.go: uploadOnly dual-leg branch must be gone")
	}
	if strings.Contains(connectUDPH2PacketConnSource, "uploadFlushTimer") {
		t.Fatal("packet_conn.go: must not use debounced uploadFlushTimer")
	}
}
