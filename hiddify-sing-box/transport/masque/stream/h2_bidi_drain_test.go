package stream

import (
	"testing"
)

func TestH2BidiDownloadDrainEnabledEnv(t *testing.T) {
	t.Setenv(EnvH2BidiDownloadDrain, "0")
	if H2BidiDownloadDrainEnabled() {
		t.Fatal("expected drain disabled with env=0")
	}
	t.Setenv(EnvH2BidiDownloadDrain, "")
	if !H2BidiDownloadDrainEnabled() {
		t.Fatal("expected drain enabled by default")
	}
}
