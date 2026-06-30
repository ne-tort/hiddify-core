//go:build masque_inttest_heavy

package inttest_test

import (
	"testing"

	masque "github.com/sagernet/sing-box/transport/masque"
)

func TestConnectIPL3PumpUploadThenDownload(t *testing.T) {
	t.Parallel()
	masque.InttestConnectIPL3PumpUploadThenDownload(t)
}

func TestConnectIPL3PumpDownloadOnly(t *testing.T) {
	t.Parallel()
	masque.InttestConnectIPL3PumpDownloadOnly(t)
}
