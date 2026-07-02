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
