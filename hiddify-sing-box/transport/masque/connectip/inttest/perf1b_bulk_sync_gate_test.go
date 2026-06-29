package inttest_test

import (
	"testing"

	"github.com/sagernet/sing-box/transport/masque/connectip/inttest"
)

func TestGATEConnectIPPerf1bBulkSyncUploadDownloadPair(t *testing.T) {
	inttest.RunGATEConnectIPPerf1bBulkSyncUploadDownloadPair(t)
}
