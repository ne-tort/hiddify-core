package tun

import (
	"testing"

	cippump "github.com/sagernet/sing-box/transport/masque/connectip/pump"
)

func TestGATEConnectIPLoopInMetricsEnvWiring(t *testing.T) {
	t.Setenv("HIDDIFY_MASQUE_CONNECT_IP_LOOPIN_METRICS", "1")
	if !cippump.LoopInMetricsEnabled() {
		t.Fatal("metrics env not enabled")
	}
	kd := &KernelTunDevice{}
	bridge := &L3OverlayBridge{kernel: kd}
	s := attachLoopInMetrics(bridge, kd)
	if s == nil || s.loopObs == nil || s.readObs == nil {
		t.Fatal("expected metrics session")
	}
	opts := cippump.TunnelOptions{}
	s.apply(&opts)
	if opts.LoopInObserver != s.loopObs {
		t.Fatal("LoopInObserver not wired")
	}
	t.Setenv("HIDDIFY_MASQUE_CONNECT_IP_LOOPIN_METRICS", "0")
	if cippump.LoopInMetricsEnabled() {
		t.Fatal("metrics should be off")
	}
	if attachLoopInMetrics(bridge, kd) != nil {
		t.Fatal("expected nil when env off")
	}
}
