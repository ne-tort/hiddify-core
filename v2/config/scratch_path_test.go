package config

import "testing"

func TestIsScratchConfigPath(t *testing.T) {
	tests := []struct {
		path string
		want bool
	}{
		{"", false},
		{"/opt/portable_data/configs/profile-id.json", false},
		{"/opt/portable_data/configs/import_out_123.tmp.json", true},
		{`C:\portable_data\configs\uuid_out_src.tmp.json`, true},
		{"/opt/portable_data/tmp/validate_in.json", true},
		{"/opt/portable_data/tmp/foo.json", true},
	}
	for _, tt := range tests {
		if got := IsScratchConfigPath(tt.path); got != tt.want {
			t.Errorf("IsScratchConfigPath(%q) = %v, want %v", tt.path, got, tt.want)
		}
	}
}

func TestProfileSourcePathScratchDoesNotCollideWithRealProfile(t *testing.T) {
	real := ProfileSourcePath("/data/configs/abc.json")
	if real != "/data/configs/abc.src" {
		t.Fatalf("unexpected real sidecar: %q", real)
	}
	scratch := ProfileSourcePath("/data/configs/abc.tmp.json")
	if scratch != "/data/configs/abc.tmp.src" {
		t.Fatalf("unexpected scratch sidecar: %q", scratch)
	}
}
