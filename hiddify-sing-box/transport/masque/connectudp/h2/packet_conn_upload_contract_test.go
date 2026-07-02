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

// TestConnectUDPH2UploadCoalesceContract locks asymmetric upload-leg bulk coalesce + bidi immediate write.
func TestConnectUDPH2UploadCoalesceContract(t *testing.T) {
	t.Parallel()
	for _, sub := range []string{
		`AppendDatagramCapsuleBuffer`,
		`uploadPending`,
		`writeUploadWireUnlocked`,
	} {
		if !strings.Contains(connectUDPH2PacketConnUploadSource, sub) && !strings.Contains(connectUDPH2PacketConnSource, sub) {
			t.Fatalf("H2 upload coalesce: missing %q", sub)
		}
	}
	if !strings.Contains(connectUDPH2PacketConnSource, `!c.uploadOnly`) {
		t.Fatal("packet_conn.go: bidi path must branch on !uploadOnly for immediate WriteDatagramCapsule")
	}
	if !strings.Contains(connectUDPH2PacketConnSource, `writeUploadUDPPayloadUnlocked`) {
		t.Fatal("packet_conn.go: bidi path must use immediate writeUploadUDPPayloadUnlocked")
	}
	if strings.Contains(connectUDPH2PacketConnSource, "uploadFlushTimer") {
		t.Fatal("packet_conn.go: must not use debounced uploadFlushTimer (UDP-6MIG-10)")
	}
}
