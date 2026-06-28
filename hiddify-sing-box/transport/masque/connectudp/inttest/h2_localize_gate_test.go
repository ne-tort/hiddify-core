package inttest_test

import (
	"testing"

	masque "github.com/sagernet/sing-box/transport/masque"
)

func TestLocalizeConnectUDPH2EchoDuplexGap(t *testing.T) {
	masque.InttestLocalizeConnectUDPH2EchoDuplexGap(t)
}

func TestLocalizeConnectUDPH2EchoDuplexGapWithFountain(t *testing.T) {
	masque.InttestLocalizeConnectUDPH2EchoDuplexGapWithFountain(t)
}
