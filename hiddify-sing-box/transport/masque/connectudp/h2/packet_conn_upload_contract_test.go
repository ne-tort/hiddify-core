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

// TestConnectUDPH2UploadInvisvImmediateWriteContract locks direct WriteDatagramCapsule per WriteTo.
func TestConnectUDPH2UploadInvisvImmediateWriteContract(t *testing.T) {
	t.Parallel()
	for _, sub := range []string{
		`h2c.WriteDatagramCapsule(c.reqBody, p)`,
		`writeUploadUDPPayloadUnlocked`,
	} {
		if !strings.Contains(connectUDPH2PacketConnUploadSource, sub) {
			t.Fatalf("packet_conn_upload.go: missing Invisv immediate write %q", sub)
		}
	}
	if strings.Contains(connectUDPH2PacketConnSource, "uploadPending") {
		t.Fatal("packet_conn.go: must not coalesce into uploadPending — Invisv/h2o immediate capsule write")
	}
	if strings.Contains(connectUDPH2PacketConnSource, "AppendDatagramCapsuleBuffer") {
		t.Fatal("packet_conn.go: must not buffer capsules before write")
	}
}
