//go:build masque_inttest_heavy && with_gvisor

package inttest

import "testing"

func runDiscriminatorL3NativeTUNLeg(t *testing.T) {
	t.Helper()
	t.Log("DISCRIMINATOR leg-B: native L3 gVisor TUN + kernel TCP post-recycle (prod path)")
	RunGATEConnectIPTunNativeL3KernelPostUploadServerRecycleDownload(t)
}
