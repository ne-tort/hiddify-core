//go:build masque_inttest_heavy

package inttest_test

import (
	"testing"

	"github.com/sagernet/sing-box/transport/masque/connectip/inttest"
)

func TestGATEConnectIPTunNativeH3PostUploadServerRecycleDownload(t *testing.T) {
	inttest.RunGATEConnectIPTunNativeH3PostUploadServerRecycleDownload(t)
}

func TestGATEConnectIPTunNativeH3PostUploadSameSessionControl(t *testing.T) {
	t.Parallel()
	inttest.RunGATEConnectIPTunNativeH3PostUploadSameSessionControl(t)
}

func TestGATEConnectIPTunNativeH3PostUploadSameSessionProbeThenBulk(t *testing.T) {
	inttest.RunGATEConnectIPTunNativeH3PostUploadSameSessionProbeThenBulk(t)
}

func TestGATEConnectIPTunNativeH3PostUploadServerRecycleSameSession(t *testing.T) {
	inttest.RunGATEConnectIPTunNativeH3PostUploadServerRecycleSameSession(t)
}

func TestGATEConnectIPTunCMPostUploadServerRecycleDownload(t *testing.T) {
	inttest.RunGATEConnectIPTunCMPostUploadServerRecycleDownload(t)
}

func TestGATEConnectIPTunCMProbeThenBulk(t *testing.T) {
	inttest.RunGATEConnectIPTunCMProbeThenBulk(t)
}
