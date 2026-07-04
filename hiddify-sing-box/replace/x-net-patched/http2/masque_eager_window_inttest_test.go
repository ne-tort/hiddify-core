//go:build masque_inttest_heavy

package http2

import "testing"

func TestMasqueInflowStockWindowBatching(t *testing.T) {
	SetMasqueDownloadEagerWindowEnabled(false)
	t.Cleanup(func() { SetMasqueDownloadEagerWindowEnabled(true) })

	var stock inflow
	stock.init(65535)
	if add := stock.add(1024); add != 0 {
		t.Fatalf("stock batch add=%d want 0 (below inflowMinRefresh)", add)
	}
	if add := stock.add(inflowMinRefresh); add != inflowMinRefresh+1024 {
		t.Fatalf("stock flush add=%d want %d", add, inflowMinRefresh+1024)
	}
}
