//go:build masque_inttest_heavy

package inttest_test

import (
	"testing"

	"github.com/sagernet/sing-box/transport/masque/connectip/inttest"
)

func TestLocalizeConnectIPUploadNativeConcurrentDownloadPollution(t *testing.T) {
	inttest.RunLocalizeConnectIPUploadNativeConcurrentDownloadPollution(t)
}

func TestLocalizeConnectIPUploadNativeDownloadFirstOrder(t *testing.T) {
	inttest.RunLocalizeConnectIPUploadNativeDownloadFirstOrder(t)
}
