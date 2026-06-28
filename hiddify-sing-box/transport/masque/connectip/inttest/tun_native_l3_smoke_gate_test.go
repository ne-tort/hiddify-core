//go:build with_gvisor

package inttest

import "testing"

func TestGATEConnectIPTunNativeL3KernelDownloadOnly(t *testing.T) {
	RunGATEConnectIPTunNativeL3KernelDownloadOnly(t)
}

func TestGATEConnectIPTunNativeL3KernelSingleChunkDownload(t *testing.T) {
	RunGATEConnectIPTunNativeL3KernelSingleChunkDownload(t)
}

func TestGATEConnectIPTunNativeL3KernelSmallChunkDownload(t *testing.T) {
	RunGATEConnectIPTunNativeL3KernelSmallChunkDownload(t)
}

func TestGATEConnectIPTunNativeL3KernelMediumChunkDownload(t *testing.T) {
	RunGATEConnectIPTunNativeL3KernelMediumChunkDownload(t)
}

func TestGATEConnectIPTunNativeL3KernelMSSChunkDownload(t *testing.T) {
	RunGATEConnectIPTunNativeL3KernelMSSChunkDownload(t)
}

func TestGATEConnectIPTunNativeL3KernelIperfReverseHeaderOnly(t *testing.T) {
	RunGATEConnectIPTunNativeL3KernelIperfReverseHeaderOnly(t)
}

func TestGATEConnectIPTunNativeL3KernelIperfReverseFull(t *testing.T) {
	RunGATEConnectIPTunNativeL3KernelIperfReverseFull(t)
}

func TestGATEConnectIPTunNativeL3KernelNcZIperfReverse(t *testing.T) {
	RunGATEConnectIPTunNativeL3KernelNcZIperfReverse(t)
}

func TestGATEConnectIPTunNativeL3DownloadOnly(t *testing.T) {
	RunGATEConnectIPTunNativeL3DownloadOnly(t)
}

func TestGATEConnectIPTunNativeL3PostNcWarmupUpload(t *testing.T) {
	RunGATEConnectIPTunNativeL3PostNcWarmupUpload(t)
}

func TestGATEConnectIPTunNativeL3UploadDownloadSmoke(t *testing.T) {
	RunGATEConnectIPTunNativeL3UploadDownloadSmoke(t)
}

func TestGATEConnectIPTunNativeL3PostUploadSameSessionProbeThenBulk(t *testing.T) {
	RunGATEConnectIPTunNativeL3PostUploadSameSessionProbeThenBulk(t)
}

func TestGATEConnectIPTunNativeL3IperfReverse(t *testing.T) {
	RunGATEConnectIPTunNativeL3IperfReverse(t)
}

func TestGATEConnectIPTunNativeL3PostUploadProbeThenIperfReverse(t *testing.T) {
	RunGATEConnectIPTunNativeL3PostUploadProbeThenIperfReverse(t)
}
