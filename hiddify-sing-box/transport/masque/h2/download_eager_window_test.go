package h2

import "testing"

func TestDownloadEagerWindowEnabledDefault(t *testing.T) {
	t.Setenv(envH2DownloadEagerWindow, "")
	if !DownloadEagerWindowEnabled() {
		t.Fatal("MASQUE_H2_DOWNLOAD_EAGER_WINDOW default must be on (H3 parity)")
	}
}

func TestDownloadEagerWindowDisabled(t *testing.T) {
	t.Setenv(envH2DownloadEagerWindow, "0")
	if DownloadEagerWindowEnabled() {
		t.Fatal("MASQUE_H2_DOWNLOAD_EAGER_WINDOW=0 must disable eager download window")
	}
}
