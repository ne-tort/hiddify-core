package inttest

import "testing"

// RunGATEConnectIPDiscriminatorPostRecyclePair runs CM synth control + L3 native TUN prod legs
// in one gate with explicit labels (TEST-3 false-green guard).
func RunGATEConnectIPDiscriminatorPostRecyclePair(t *testing.T) {
	t.Helper()
	t.Log("=== DISCRIMINATOR post-recycle pair (TEST-3): leg-A CM synth vs leg-B L3 native TUN ===")

	t.Run("leg_A_CM_synth_control", func(t *testing.T) {
		t.Log("DISCRIMINATOR leg-A: CM TUN routing (DialContext synth — false-green control)")
		RunGATEConnectIPTunCMPostUploadServerRecycleDownload(t)
	})

	t.Run("leg_B_L3_native_TUN_prod", func(t *testing.T) {
		runDiscriminatorL3NativeTUNLeg(t)
	})

	t.Log("=== DISCRIMINATOR post-recycle pair: both legs PASS ===")
}
