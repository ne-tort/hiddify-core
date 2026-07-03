package inttest_test

import (
	"runtime"
	"testing"
)

const skipH3MultiDatagramWindowsReason = "H3 multi-datagram echo reassembly order unreliable on Windows loopback"

func skipH3MultiDatagramWindows(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip(skipH3MultiDatagramWindowsReason)
	}
}
