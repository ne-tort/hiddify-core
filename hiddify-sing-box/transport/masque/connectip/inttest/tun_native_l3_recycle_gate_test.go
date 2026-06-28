//go:build with_gvisor

package inttest

import "testing"

func TestGATEConnectIPTunNativeL3PostUploadServerRecycleDownload(t *testing.T) {
	RunGATEConnectIPTunNativeL3PostUploadServerRecycleDownload(t)
}
