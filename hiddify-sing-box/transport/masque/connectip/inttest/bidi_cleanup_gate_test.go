package inttest_test

import (
	"testing"

	"github.com/sagernet/sing-box/transport/masque/connectip/inttest"
)

func TestGATEConnectIPBidiCleanupAfterUploadDownload(t *testing.T) {
	inttest.RunGATEConnectIPBidiCleanupAfterUploadDownload(t)
}
