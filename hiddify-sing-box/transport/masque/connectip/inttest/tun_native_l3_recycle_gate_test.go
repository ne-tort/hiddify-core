//go:build masque_inttest_heavy && with_gvisor

package inttest

import "testing"

func TestGATEConnectIPTunNativeL3PostUploadServerRecycleDownload(t *testing.T) {
	RunGATEConnectIPTunNativeL3PostUploadServerRecycleDownload(t)
}
