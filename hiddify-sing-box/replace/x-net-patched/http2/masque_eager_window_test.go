package http2

import "testing"

func TestMasqueInflowEagerWindowUpdatePerRead(t *testing.T) {
	SetMasqueDownloadEagerWindowEnabled(true)
	t.Cleanup(func() { SetMasqueDownloadEagerWindowEnabled(false) })

	if !masqueDownloadEagerWindowEnabled() {
		t.Fatal("eager download WINDOW must be on for this test")
	}
	var eager inflow
	eager.init(65535)
	if add := eager.add(1024); add != 1024 {
		t.Fatalf("eager add=%d want 1024", add)
	}
	if add := eager.add(512); add != 512 {
		t.Fatalf("eager second add=%d want 512", add)
	}
}
