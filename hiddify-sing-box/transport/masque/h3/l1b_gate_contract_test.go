package h3

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// l1bSynthGatePatterns maps SYNTH-TEST-PLAN P1 L1b IDs to substrings that must appear in the
// L1b H3 gate -run pattern (go-test-masque-gates.ps1). S53 extends coverage beyond the
// original BidiDuplex|DuplexCoord anchor.
var l1bSynthGatePatterns = map[string]string{
	"S6":  "WrapBidiWindow",
	"S7":  "BidiUploadWakeDuringDownload",
	"S8":  "MasqueH3Duplex",
	"S9":  "MasqueH3Duplex",
	"S26": "DuplexCoord",
	"S27": "TunnelConnDuplexCoordEndToEnd",
	"S30": "DuplexDownloadActiveFramerBoostLink",
	"S32": "MasqueH3WriteToDownloadDrain",
	"S33": "DuplexCoord",
	"S60": "MasqueH3Duplex",
	"S61": "CloseDuringActiveDownload",
	"S62": "QuicConnectUploadChunkParity",
	"S64": "H3DuplexConnWakeReceiveVsDeliveryEnvMatrix",
}

func readMasqueGateScript(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	dir := wd
	for range 12 {
		candidates := []string{
			filepath.Join(dir, "scripts", "go-test-masque-gates.ps1"),
			filepath.Join(dir, "..", "scripts", "go-test-masque-gates.ps1"),
			filepath.Join(dir, "..", "..", "scripts", "go-test-masque-gates.ps1"),
			filepath.Join(dir, "..", "..", "..", "scripts", "go-test-masque-gates.ps1"),
		}
		for _, path := range candidates {
			data, err := os.ReadFile(path)
			if err == nil {
				return string(data)
			}
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	t.Fatalf("go-test-masque-gates.ps1 not found (run from hiddify-sing-box checkout)")
	return ""
}

func l1bGateRunPattern(gateScript string) string {
	idx := strings.Index(gateScript, `Invoke-MasqueGate "L1b H3`)
	if idx < 0 {
		return ""
	}
	chunk := gateScript[idx:]
	start := strings.Index(chunk, `"H3Connect`)
	if start < 0 {
		return ""
	}
	rest := chunk[start+1:]
	end := strings.Index(rest, `"`)
	if end < 0 {
		return ""
	}
	return rest[:end]
}

// TestMasqueL1bSynthGatePatternContract (S53): PR gate -run must cover every P1 L1b synth test name.
func TestMasqueL1bSynthGatePatternContract(t *testing.T) {
	t.Parallel()
	gate := readMasqueGateScript(t)
	pattern := l1bGateRunPattern(gate)
	if pattern == "" {
		t.Fatal("L1b H3 gate -run pattern not found in go-test-masque-gates.ps1")
	}
	for id, fragment := range l1bSynthGatePatterns {
		if !strings.Contains(pattern, fragment) {
			t.Errorf("L1b gate pattern missing %s (%q)", id, fragment)
		}
	}
	for _, anchor := range []string{
		"TunnelConnWakeBidiSend",
		"BidiDuplex",
		"DuplexCoord",
		"InterleaveDuplex",
		"MasqueInterleaveDuplexTransferCPUBudget",
		"WrapBidiWindowWriteTo",
		"SetBidiDownloadActiveOnRealQUIC",
	} {
		if !strings.Contains(pattern, anchor) {
			t.Errorf("L1b gate pattern missing anchor %q", anchor)
		}
	}
}
