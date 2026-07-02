package masque

import (
	"sync/atomic"
	"testing"
)

type udpDeselectTestOutbound struct {
	planeClosed atomic.Bool
}

func (d *udpDeselectTestOutbound) CloseConnectUDPPlaneOnDeselect() {
	d.planeClosed.Store(true)
}

func TestNotifyConnectUDPPlaneDeselected(t *testing.T) {
	t.Parallel()
	prev := &udpDeselectTestOutbound{}
	NotifyConnectUDPPlaneDeselected(prev)
	if !prev.planeClosed.Load() {
		t.Fatal("expected CloseConnectUDPPlaneOnDeselect on deselected outbound")
	}
	NotifyConnectUDPPlaneDeselected(nil)
	var _ ConnectUDPPlaneDeselector = (*udpDeselectTestOutbound)(nil)
}
