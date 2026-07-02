package h2

import "testing"

func TestLegProfileForStreamRole(t *testing.T) {
	if legProfileForStreamRole(streamRoleUpload) != LegProfileUpload {
		t.Fatal("upload role")
	}
	if legProfileForStreamRole(streamRoleDownload) != LegProfileDownloadFountain {
		t.Fatal("download role")
	}
	if legProfileForStreamRole(streamRoleBidi) != LegProfileBidi {
		t.Fatal("bidi maps to immediate S2C profile")
	}
}
