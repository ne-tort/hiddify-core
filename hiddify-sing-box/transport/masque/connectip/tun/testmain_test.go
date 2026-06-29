package tun

import (
	"os"
	"testing"
)

func TestMain(m *testing.M) {
	// Synth gates exercise PERF-1b NoWake; prod Docker default is sync egress.
	os.Setenv("HIDDIFY_MASQUE_CONNECT_IP_TUN_BULK_NOWAKE", "1")
	os.Exit(m.Run())
}
