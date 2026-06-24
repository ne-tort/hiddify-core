package quic

import "testing"

// TestMasqueWakeBidiConnOnReceiveReadProdDefault documents prod default (opt-out with =0).
func TestMasqueWakeBidiConnOnReceiveReadProdDefault(t *testing.T) {
	if !masqueWakeBidiConnOnReceiveRead() {
		t.Fatal("MASQUE_QUIC_BIDI_CONN_WAKE: prod default is enabled when unset")
	}
}

// TestMasqueWakeBidiDuplexSkipsConnWhenDisabled verifies MasqueWakeBidiDuplex honors the gate.
func TestMasqueWakeBidiDuplexSkipsConnWhenDisabled(t *testing.T) {
	prev := masqueWakeBidiConnOnReceiveReadEnabled
	t.Cleanup(func() { masqueWakeBidiConnOnReceiveReadEnabled = prev })

	masqueWakeBidiConnOnReceiveReadEnabled = false
	var connWakes int
	restore := SetMasqueWakeConnSendHook(func() { connWakes++ })
	t.Cleanup(restore)

	MasqueWakeBidiDuplex(nil)
	if connWakes != 0 {
		t.Fatalf("conn wakes=%d want 0 when bidi conn wake disabled", connWakes)
	}
}
