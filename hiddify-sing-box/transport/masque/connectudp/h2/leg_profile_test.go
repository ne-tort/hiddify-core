package h2

import "testing"

func TestLegProfileForStreamRole(t *testing.T) {
	if legProfileForStreamRole(streamRoleUpload) != LegProfileUpload {
		t.Fatal("upload role")
	}
	if legProfileForStreamRole(streamRoleDownload) != LegProfileDownloadFountain {
		t.Fatal("download role")
	}
	if legProfileForStreamRole(streamRoleBidi) != LegProfileEchoBidi {
		t.Fatal("bidi role")
	}
}

func TestLegProfileUploadNoCoalesceTimer(t *testing.T) {
	if !LegProfileUpload.uploadNoCoalesceTimer() {
		t.Fatal("upload profile skips debounce timer")
	}
	if LegProfileEchoBidi.uploadNoCoalesceTimer() {
		t.Fatal("echo keeps timer path")
	}
}

func TestLegProfileUploadImmediateFlush(t *testing.T) {
	if !LegProfileUpload.uploadImmediateFlush() {
		t.Fatal("upload profile immediate flush (thin) default-on")
	}
	if LegProfileEchoBidi.uploadImmediateFlush() {
		t.Fatal("echo bidi must not use upload thin flush")
	}
}

func TestLegProfileServerFountainBulkFlush(t *testing.T) {
	if !LegProfileDownloadFountain.serverDownlinkBulkImmediateFlush() {
		t.Fatal("fountain bulk no-timer flush")
	}
	if LegProfileEchoBidi.serverDownlinkBulkImmediateFlush() {
		t.Fatal("echo bidi must not use fountain bulk flush")
	}
}

// TestLegProfileAsyncDownlinkPumpByRole locks leg-aware downlink pump (UDP-M3-08 SIMPLIFY).
func TestLegProfileAsyncDownlinkPumpByRole(t *testing.T) {
	if !LegProfileDownloadFountain.usesAsyncDownlinkPump() {
		t.Fatal("fountain S2C uses async downlink pump")
	}
	if !LegProfileEchoBidi.usesAsyncDownlinkPump() {
		t.Fatal("echo bidi uses async downlink pump")
	}
	if LegProfileUpload.usesAsyncDownlinkPump() {
		t.Fatal("upload leg must not run downlink pump")
	}
}

// TestLegProfileUploadCoalesceIsEchoOnly documents upload coalesce scope (UDP-M3-09 SIMPLIFY).
func TestLegProfileUploadCoalesceIsEchoOnly(t *testing.T) {
	if LegProfileUpload == LegProfileEchoBidi {
		t.Fatal("upload profile must not debounce-coalesce")
	}
	if LegProfileDownloadFountain == LegProfileEchoBidi {
		t.Fatal("fountain must not use echo coalesce path")
	}
}
