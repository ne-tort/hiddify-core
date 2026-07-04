package http2

import "testing"

func TestMasqueDownloadPokeReceiveWindowOnce(t *testing.T) {
	SetMasqueDownloadEagerWindowEnabled(true)
	t.Cleanup(func() { SetMasqueDownloadEagerWindowEnabled(true) })

	cs := &clientStream{
		masqueExtendedConnect: true,
		cc:                    &ClientConn{},
	}
	cs.cc.mu.Lock()
	cs.inflow.init(65535)
	cs.cc.inflow.init(65535)
	cs.cc.mu.Unlock()

	cs.masquePokeDownloadReceiveWindowOnce()
	cs.masquePokeDownloadReceiveWindowOnce()
}
