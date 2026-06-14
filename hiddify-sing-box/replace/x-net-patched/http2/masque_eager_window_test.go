package http2

import "testing"

func TestMasqueInflowEagerWindowUpdatePerRead(t *testing.T) {
	t.Setenv("MASQUE_H2_DOWNLOAD_EAGER_WINDOW", "1")
	var eager inflow
	eager.init(65535)
	if add := eager.add(1024); add != 1024 {
		t.Fatalf("eager add=%d want 1024", add)
	}
	if add := eager.add(512); add != 512 {
		t.Fatalf("eager second add=%d want 512", add)
	}

	t.Setenv("MASQUE_H2_DOWNLOAD_EAGER_WINDOW", "0")
	var stock inflow
	stock.init(65535)
	if add := stock.add(1024); add != 0 {
		t.Fatalf("stock batch add=%d want 0 (below inflowMinRefresh)", add)
	}
	if add := stock.add(inflowMinRefresh); add != inflowMinRefresh+1024 {
		t.Fatalf("stock flush add=%d want %d", add, inflowMinRefresh+1024)
	}
}
