//go:build with_gvisor

package inttest_test

import (
	"testing"

	"github.com/sagernet/sing-box/transport/masque/connectip/inttest"
)

func TestGATEConnectIPTunGVisorPostUploadServerRecycleDownload(t *testing.T) {
	inttest.RunGATEConnectIPTunGVisorPostUploadServerRecycleDownload(t)
}

func TestGATEConnectIPTunGVisorUploadThenRecycleDownload(t *testing.T) {
	inttest.RunGATEConnectIPTunGVisorUploadThenRecycleDownload(t)
}

func TestGATEConnectIPTunGVisorRelayCorruptsPostRecycle(t *testing.T) {
	inttest.RunGATEConnectIPTunGVisorRelayCorruptsPostRecycle(t)
}

func TestGATEConnectIPTunNativeL3SameSessionRebindRecycle(t *testing.T) {
	inttest.RunGATEConnectIPTunNativeL3SameSessionRebindRecycle(t)
}
