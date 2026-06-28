package masque

import (
	"sync/atomic"
	"testing"
)

type deselectTestOutbound struct {
	planeClosed atomic.Bool
}

func (d *deselectTestOutbound) CloseConnectIPPlaneOnDeselect() {
	d.planeClosed.Store(true)
}

func TestNotifyConnectIPPlaneDeselected(t *testing.T) {
	t.Parallel()
	prev := &deselectTestOutbound{}
	NotifyConnectIPPlaneDeselected(prev)
	if !prev.planeClosed.Load() {
		t.Fatal("expected CloseConnectIPPlaneOnDeselect on deselected outbound")
	}
	NotifyConnectIPPlaneDeselected(nil)
	var _ ConnectIPPlaneDeselector = (*deselectTestOutbound)(nil)
}
