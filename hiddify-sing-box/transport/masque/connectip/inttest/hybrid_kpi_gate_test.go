package inttest_test

import (
	"testing"

	"github.com/sagernet/sing-box/transport/masque/connectip/inttest"
)

func TestConnectIPHybridConnectStreamH2DownloadKPI(t *testing.T) {
	inttest.RunConnectIPHybridConnectStreamH2DownloadKPI(t)
}

func TestConnectIPHybridConnectStreamH3DownloadKPI(t *testing.T) {
	inttest.RunConnectIPHybridConnectStreamH3DownloadKPI(t)
}
