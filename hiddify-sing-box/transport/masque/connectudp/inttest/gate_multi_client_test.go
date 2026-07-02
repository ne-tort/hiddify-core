package inttest_test

import (
	"testing"

	masque "github.com/sagernet/sing-box/transport/masque"
)

func TestGATEConnectUDPMultiClientIsolationH3(t *testing.T) {
	masque.InttestGATEConnectUDPMultiClientIsolationH3(t)
}

func TestGATEConnectUDPMultiClientIsolationH2(t *testing.T) {
	masque.InttestGATEConnectUDPMultiClientIsolationH2(t)
}
