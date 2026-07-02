package h2

import (
	"strings"
	"testing"

	_ "embed"
)

//go:embed packet_conn.go
var h2PacketConnSource string

//go:embed packet_conn_downlink.go
var h2PacketConnDownlinkSource string

//go:embed packet_conn_upload.go
var h2PacketConnUploadSource string

//go:embed leg_profile.go
var h2LegProfileSource string

//go:embed asymmetric_packet_conn.go
var h2AsymmetricPacketConnSource string

//go:embed dial.go
var h2DialSource string

//go:embed server.go
var h2ServerSource string

//go:embed server_asymmetric.go
var h2ServerAsymmetricSource string

// TestH2ServeBidiH2oImmediateRelay locks h2o 1:1 S2C + direct C2S on full-duplex ServeH2.
func TestH2ServeBidiH2oImmediateRelay(t *testing.T) {
	t.Parallel()
	if !strings.Contains(h2ServerSource, "RelayH2ConnectDownlinkImmediate") {
		t.Fatal("server.go: bidi ServeH2 must use RelayH2ConnectDownlinkImmediate (h2o udp_on_read)")
	}
	if !strings.Contains(h2ServerSource, "DirectH2OnwardUplink") {
		t.Fatal("server.go: bidi ServeH2 must use DirectH2OnwardUplink (h2o udp_write_core)")
	}
	if strings.Contains(h2ServerSource, "RelayH2ConnectDownlink(relayCtx") {
		t.Fatal("server.go: bidi must not use batch S2C downlink relay")
	}
}

// TestH2ClientProdSourceHasNoLegacyPump locks CUT of async downlink / coalesce timer / EchoBidi (UDP-6MIG-10).
func TestH2ClientProdSourceHasNoLegacyPump(t *testing.T) {
	t.Parallel()
	forbidden := []string{
		"runDownlinkPump",
		"ensureDownlinkPump",
		"LegProfileEchoBidi",
		"EchoBidi",
		"AsyncDownlink",
		"armUploadFlushTimer",
		"uploadFlushTimer",
		"h2UploadBulkEnterGap",
		"bulkUpload",
		"markDuplexPeerActive",
		"CountLeadingDatagramCapsule512Wire",
		"downlinkQueue",
		"uploadCh",
		"uploadWorker",
		"borrowUploadPayload",
		"uploadPayloadPool",
		"SendBurstViews",
	}
	for _, src := range []struct {
		name string
		body string
	}{
		{"packet_conn.go", h2PacketConnSource},
		{"packet_conn_downlink.go", h2PacketConnDownlinkSource},
		{"packet_conn_upload.go", h2PacketConnUploadSource},
		{"leg_profile.go", h2LegProfileSource},
		{"asymmetric_packet_conn.go", h2AsymmetricPacketConnSource},
		{"dial.go", h2DialSource},
		{"server.go", h2ServerSource},
	} {
		for _, needle := range forbidden {
			if strings.Contains(src.body, needle) {
				t.Fatalf("%s must not contain legacy H2 pump/timer %q", src.name, needle)
			}
		}
	}
}

// TestH2AsymmetricDownloadUsesFountainRelay locks batch S2C on download-only leg (bidi stays immediate).
func TestH2AsymmetricDownloadUsesFountainRelay(t *testing.T) {
	t.Parallel()
	if !strings.Contains(h2ServerAsymmetricSource, "RelayH2ConnectDownlinkFountain") {
		t.Fatal("server_asymmetric.go: download leg must use RelayH2ConnectDownlinkFountain (fountain batch)")
	}
	if strings.Contains(h2ServerAsymmetricSource, "RelayH2ConnectDownlinkImmediate") {
		t.Fatal("server_asymmetric.go: download leg must not use immediate 1:1 S2C relay")
	}
}
