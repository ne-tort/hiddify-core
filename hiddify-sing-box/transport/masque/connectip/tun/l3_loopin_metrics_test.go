package tun

import (
	"testing"

	cippump "github.com/sagernet/sing-box/transport/masque/connectip/pump"
)

func TestGATEConnectIPLoopInMetricsDisabledInProd(t *testing.T) {
	if cippump.LoopInMetricsEnabled() {
		t.Fatal("LoopIn metrics must be disabled in prod")
	}
	kd := &KernelTunDevice{}
	bridge := &L3OverlayBridge{kernel: kd}
	if attachLoopInMetrics(bridge, kd) != nil {
		t.Fatal("expected nil metrics session when disabled")
	}
}
