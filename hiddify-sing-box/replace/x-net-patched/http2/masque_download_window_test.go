package http2

import (
	"bufio"
	"bytes"
	"sync"
	"testing"
)

func TestMasqueDownloadPokeReceiveWindowOnce(t *testing.T) {
	SetMasqueDownloadEagerWindowEnabled(true)
	t.Cleanup(func() { SetMasqueDownloadEagerWindowEnabled(false) })

	var wire bytes.Buffer
	bw := bufio.NewWriter(&wire)
	cc := &ClientConn{
		bw: bw,
		fr: NewFramer(bw, nil),
	}
	cc.cond = sync.NewCond(&cc.mu)
	cs := &clientStream{
		masqueExtendedConnect: true,
		cc:                    cc,
		ID:                    1,
	}
	cc.mu.Lock()
	cs.inflow.init(65535)
	cc.inflow.init(65535)
	cc.mu.Unlock()

	cs.masquePokeDownloadReceiveWindowOnce()
	cs.masquePokeDownloadReceiveWindowOnce() // Once: no second WU storm

	if wire.Len() == 0 {
		t.Fatal("expected WINDOW_UPDATE frames after poke")
	}
}
