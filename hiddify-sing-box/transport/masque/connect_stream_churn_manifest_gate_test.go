package masque_test

// GATE-CHURN-MANIFEST: documents synth churn gates required before field HTTP soak.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGATEH3ConnectStreamChurnGatesPresent(t *testing.T) {
	t.Parallel()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	required := []string{
		"TestGATEH3ConnectStreamDirectSessionChurnNoPoison",
		"TestGATEH3ConnectStreamDirectChurn90SubMaxStreams",
		"TestGATEH3ConnectStreamSocksCMSequentialChurnNoPoison",
		"TestGATEH3ConnectStreamSocksCMParallelChurnNoPoison",
		"TestGATEH3ConnectStreamParallelCanceledParentDialSucceeds",
		"TestGATEH3ConnectStreamQUICMaxStreamsBackpressure",
		"TestGATEH3ConnectStreamBrowserParallelParent30sDeadline",
		"TestGATEH3ConnectStreamBrowserBurstWithHeldStreams",
		"TestGATEH3ConnectStreamBenchAbortStaleQUICPostProbe",
		"TestGATEH3ConnectStreamSequentialBenchAbortBudgetProbe",
	}
	for _, name := range required {
		found := false
		for _, file := range []string{
			"connect_stream_synth_soak_localize_test.go",
			"connect_stream_dial_gate_test.go",
			"connect_stream_session_death_gate_test.go",
		} {
			src, err := os.ReadFile(filepath.Join(wd, file))
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(src), name) {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("missing churn gate %s in synth localize/budget tests", name)
		}
	}
}
