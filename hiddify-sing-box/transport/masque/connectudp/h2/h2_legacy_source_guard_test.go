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

//go:embed dial.go
var h2DialSource string

//go:embed server.go
var h2ServerSource string

//go:embed handler_entry.go
var h2HandlerEntrySource string

// TestH2ServeBidiFountainRelay locks prod S2C batch flush + direct C2S on full-duplex ServeH2.
// Capsule encode stays 1 UDP↔1 capsule; wire Flush is per RX batch (not per-capsule).
func TestH2ServeBidiFountainRelay(t *testing.T) {
	t.Parallel()
	if !strings.Contains(h2ServerSource, "RelayH2ConnectDownlinkFountain") {
		t.Fatal("server.go: bidi ServeH2 must use RelayH2ConnectDownlinkFountain (batch Flush)")
	}
	if !strings.Contains(h2ServerSource, "DirectH2OnwardUplink") {
		t.Fatal("server.go: bidi ServeH2 must use DirectH2OnwardUplink (h2o udp_write_core)")
	}
	if strings.Contains(h2ServerSource, "RelayH2ConnectDownlinkImmediate(") {
		t.Fatal("server.go: bidi ServeH2 must not call RelayH2ConnectDownlinkImmediate (per-capsule Flush)")
	}
	if strings.Contains(h2ServerSource, "RelayH2ConnectDownlink(relayCtx") {
		t.Fatal("server.go: bidi must not use legacy batch S2C downlink relay name")
	}
}

// TestH2ClientProdSourceHasNoLegacyPump locks CUT of async downlink / coalesce timer / EchoBidi / dual-leg.
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
		"dialH2OverlayAsymmetric",
		"NewAsymmetricPacketConn",
		"SessionRegistry",
		"Masque-Udp-Stream-Role",
		"MasqueUDPStreamRoleHeader",
	}
	for _, src := range []struct {
		name string
		body string
	}{
		{"packet_conn.go", h2PacketConnSource},
		{"packet_conn_downlink.go", h2PacketConnDownlinkSource},
		{"packet_conn_upload.go", h2PacketConnUploadSource},
		{"dial.go", h2DialSource},
		{"server.go", h2ServerSource},
	} {
		for _, needle := range forbidden {
			if strings.Contains(src.body, needle) {
				t.Fatalf("%s must not contain legacy H2 pump/timer/asym %q", src.name, needle)
			}
		}
	}
}

// TestH2DialIsRFCBidiSingleStream locks approach A: one CONNECT, no dual-leg dial.
func TestH2DialIsRFCBidiSingleStream(t *testing.T) {
	t.Parallel()
	if !strings.Contains(h2DialSource, "dialH2OverlayBidi") {
		t.Fatal("dial.go: must dial via dialH2OverlayBidi")
	}
	if !strings.Contains(h2DialSource, "NewConnectUploadShallowPipe") {
		t.Fatal("dial.go: bidi must use shallow upload pipe")
	}
	if strings.Contains(h2DialSource, "streamRoleDownload") || strings.Contains(h2DialSource, "streamRoleUpload") {
		t.Fatal("dial.go: must not set asymmetric stream roles")
	}
	if !strings.Contains(h2HandlerEntrySource, "ServeH2(") {
		t.Fatal("handler_entry.go: must call ServeH2")
	}
	if strings.Contains(h2HandlerEntrySource, "ServeH2FromRequest") {
		t.Fatal("handler_entry.go: ServeH2FromRequest (asym router) must be gone")
	}
}
