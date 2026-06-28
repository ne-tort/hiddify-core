//go:build with_gvisor

package inttest

// Native L3 TUN post-upload server recycle (IP-AUDIT-P0-01 gate).

import "testing"

// RunGATEConnectIPTunNativeL3PostUploadServerRecycleDownload exercises ARCH-2 L3 path:
// gVisor TUN upload → server restart → fresh session → gVisor TUN download.
func RunGATEConnectIPTunNativeL3PostUploadServerRecycleDownload(t *testing.T) {
	t.Helper()
	RunGATEConnectIPTunGVisorUploadThenRecycleDownload(t)
}
