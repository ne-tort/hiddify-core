//go:build masque_inttest_heavy

package inttest_test

import (
	"testing"

	"github.com/sagernet/sing-box/transport/masque"
)

func TestConnectIPTunPostUploadDownload(t *testing.T) {
	masque.InttestConnectIPTunPostUploadDownload(t)
}

func TestConnectIPDockerTUNKPIInProcGuard(t *testing.T) {
	masque.InttestConnectIPDockerTUNKPIInProcGuard(t)
}
