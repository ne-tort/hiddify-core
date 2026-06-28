//go:build !with_gvisor

package inttest

import "testing"

func runDiscriminatorL3NativeTUNLeg(t *testing.T) {
	t.Helper()
	t.Skip("DISCRIMINATOR leg-B: skipped without -tags with_gvisor; run TestGATEConnectIPNativeL3SameSessionReopenAfterUploadSynth on Windows")
}
