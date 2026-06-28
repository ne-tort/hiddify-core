package inttest_test

import (
	"testing"

	"github.com/sagernet/sing-box/transport/masque/connectip/inttest"
)

func TestGATEConnectIPLifecycleGoroutineAfterClose(t *testing.T) {
	inttest.RunGATEConnectIPLifecycleGoroutineAfterClose(t)
}

func TestGATEConnectIPLifecycleGoroutineAfterRecycle(t *testing.T) {
	inttest.RunGATEConnectIPLifecycleGoroutineAfterRecycle(t)
}

func TestGATEConnectIPRelayTeardownDownloadOnly(t *testing.T) {
	inttest.RunGATEConnectIPRelayTeardownDownloadOnly(t)
}

func TestGATEConnectIPSessionCloseMidBulkNoLeak(t *testing.T) {
	inttest.RunGATEConnectIPSessionCloseMidBulkNoLeak(t)
}
