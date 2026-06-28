//go:build linux && with_gvisor

package inttest_test

import (
	"testing"

	"github.com/sagernet/sing-box/transport/masque/connectip/inttest"
)

// TestGATEConnectIPTunNativeL3KernelIperfReverseHeaderOnly localizes WriteIngress S2C without bulk.
func TestGATEConnectIPTunNativeL3KernelIperfReverseHeaderOnly(t *testing.T) {
	inttest.RunGATEConnectIPTunNativeL3KernelIperfReverseHeaderOnly(t)
}

// TestGATEConnectIPTunNativeL3KernelPostNcUpload is prod parity: real tun + WriteIngress + OS kernel TCP.
func TestGATEConnectIPTunNativeL3KernelPostNcUpload(t *testing.T) {
	inttest.RunGATEConnectIPTunNativeL3PostNcWarmupUpload(t)
}

// TestGATEConnectIPTunNativeL3KernelUploadDownload is full TUN L3 kernel path smoke.
func TestGATEConnectIPTunNativeL3KernelUploadDownload(t *testing.T) {
	inttest.RunGATEConnectIPTunNativeL3UploadDownloadSmoke(t)
}
