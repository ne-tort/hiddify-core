package conn

import "testing"

func TestH3LegRoleFromStreamRole(t *testing.T) {
	if got := H3LegRoleFromStreamRole("download"); got != H3LegDownload {
		t.Fatalf("download: got %v want %v", got, H3LegDownload)
	}
	if got := H3LegRoleFromStreamRole("upload"); got != H3LegUpload {
		t.Fatalf("upload: got %v want %v", got, H3LegUpload)
	}
	if got := H3LegRoleFromStreamRole(""); got != H3LegBidi {
		t.Fatalf("empty: got %v want %v", got, H3LegBidi)
	}
}
