package masque

import (
	"strings"
	"testing"
)

// l0SessionGatePatterns maps A6 session/runtime P8 prod dial guards in go-test-masque-gates.ps1.
var l0SessionGatePatterns = map[string]string{
	"A6-1": "RuntimeConnectStreamDialP8Floor",
	"A5-1": "P8FloorAfterExperimental",
	"A6-3": "FinalizeRestoresBulkFC",
}

// TestMasqueL0SessionGatePatternContract (A6-2): L0 runtime + session gates must anchor P8 dial guards.
func TestMasqueL0SessionGatePatternContract(t *testing.T) {
	t.Parallel()
	ps1 := readMasqueGateScript(t)
	sh := readMasqueGateShell(t)

	runtimePS1 := gateRunPattern(ps1, `Invoke-MasqueGate "L0 runtime dial shape"`)
	runtimeSH := gateRunPattern(sh, `invoke_masque_gate "L0 runtime dial shape"`)
	sessionPS1 := gateRunPattern(ps1, `Invoke-MasqueGate "L0 session"`)
	sessionSH := gateRunPattern(sh, `invoke_masque_gate "L0 session"`)

	if runtimePS1 == "" || runtimeSH == "" {
		t.Fatal("L0 runtime dial shape -run pattern not found in gate scripts")
	}
	if sessionPS1 == "" || sessionSH == "" {
		t.Fatal("L0 session -run pattern not found in gate scripts")
	}

	for id, fragment := range l0SessionGatePatterns {
		switch id {
		case "A6-1":
			if !strings.Contains(runtimePS1, fragment) || !strings.Contains(runtimeSH, fragment) {
				t.Errorf("L0 runtime gate missing %s (%q)", id, fragment)
			}
		default:
			if !strings.Contains(sessionPS1, fragment) || !strings.Contains(sessionSH, fragment) {
				t.Errorf("L0 session gate missing %s (%q)", id, fragment)
			}
		}
	}
}
