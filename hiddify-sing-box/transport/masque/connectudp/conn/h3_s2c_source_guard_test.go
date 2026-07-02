package conn

import (
	"strings"
	"testing"

	_ "embed"
)

//go:embed h3.go
var h3ConnSource string

//go:embed opt_c2s.go
var h3C2SSource string

//go:embed h3_masque_leg.go
var h3MasqueLegSource string

// TestH3ClientS2CSourceHasNoPrefetchPump locks CUT of legacy bg prefetch (UDP-6MIG-01).
func TestH3ClientS2CSourceHasNoPrefetchPump(t *testing.T) {
	t.Parallel()
	forbidden := []string{
		"runS2CPrefetchPump",
		"h3S2CPrefetchRing",
		"s2cPrefetchEnabled",
		"drainTryReceiveIntoPrefetch",
		"WakeMasqueClientAfterDatagramReceiveFrom",
		"h3S2CInlinePending",
	}
	for _, needle := range forbidden {
		if strings.Contains(h3ConnSource, needle) {
			t.Fatalf("h3.go must not contain legacy S2C %q", needle)
		}
	}
}

// TestH3ClientC2SSyncSendDatagram locks masque-go sync SendDatagram on WriteTo (QUIC backpressure; no NoWake batch).
func TestH3ClientC2SSyncSendDatagram(t *testing.T) {
	t.Parallel()
	for _, needle := range []string{"writeCh", "pump()"} {
		if strings.Contains(h3C2SSource, needle) {
			t.Fatalf("opt_c2s.go must not contain %q", needle)
		}
	}
	for _, needle := range []string{"SendDatagram", "FlushProxiedIPDatagramSend", "DatagramSendBacklog", "awaitDatagramSendDrain"} {
		if !strings.Contains(h3C2SSource, needle) {
			t.Fatalf("opt_c2s.go must contain sync C2S backpressure %q", needle)
		}
	}
	if strings.Contains(h3C2SSource, "SendDatagramNoWake") {
		t.Fatal("opt_c2s.go must not use SendDatagramNoWake (UDP-REF-H3-02 CUT)")
	}
	if !strings.Contains(h3ConnSource, "h3C2SWriter") {
		t.Fatal("h3.go must wire h3C2SWriter from opt_c2s.go")
	}
}

// TestH3AsymmetricDownloadLegArmsQUICReceiveActive locks P2 download receive-active for sibling upload FC.
func TestH3AsymmetricDownloadLegArmsQUICReceiveActive(t *testing.T) {
	t.Parallel()
	combined := h3ConnSource + h3C2SSource + h3MasqueLegSource
	for _, needle := range []string{
		"MasqueSetBidiDownloadReceiveActive",
		"MasqueSetPeerDuplexLazyFC",
		"H3LegDownload",
	} {
		if !strings.Contains(combined, needle) {
			t.Fatalf("h3 asymmetric download leg must arm QUIC receive-active (%q)", needle)
		}
	}
	if strings.Contains(combined, "MasqueSetBidiDownloadActive(") {
		t.Fatal("must use MasqueSetBidiDownloadReceiveActive, not send-boost MasqueSetBidiDownloadActive")
	}
}

// TestH3AsymmetricDownloadLegKeepsStreamOpen locks S2C ReceiveDatagram until PacketConn Close.
func TestH3AsymmetricDownloadLegKeepsStreamOpen(t *testing.T) {
	t.Parallel()
	if !strings.Contains(h3ConnSource, "cfg.LegRole == H3LegBidi") {
		t.Fatal("h3.go must only close request stream after skip on bidi leg (asymmetric download stays open)")
	}
}
