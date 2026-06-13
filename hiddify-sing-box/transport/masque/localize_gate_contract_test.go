package masque

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// perfLocalizeGatePatterns maps SYNTH-TEST-PLAN P3 S80 WriteTo anchors that must appear in the
// masque-perf-localize CI -run pattern (.github/workflows/ci.yml).
var perfLocalizeGatePatterns = map[string]string{
	"S1":  "BenchCeiling",
	"S3":  "ConnectStreamLocalizeDownloadWriteTo",
	"S63": "MeasureTCPDownloadWriteTo",
	"S94": "ConnectStreamLocalizeBottleneckWriteTo",
}

// l2SynthGatePatterns maps P0 synth IDs covered by the blocking L2 synth anchor gate (S81).
var l2SynthGatePatterns = map[string]string{
	"S1":  "BenchCeiling",
	"S2":  "BypassMatrix",
	"S3":  "ConnectStreamLocalizeDownloadWriteTo",
	"S5":  "ConnectStreamParallelStreams",
	"S5b": "ConnectStreamDuplexWriteTo",
	"S18": "ConnectStreamDownloadLayer",
	"S19": "ConnectStreamCPUBudget",
	"S48": "PprofSymbol",
	"S63": "MeasureTCPDownloadWriteTo",
	"S83": "ReadPathSkipsDownloadActive",
	"S84": "WindowedBidiConnThroughput",
	"S92": "InstantDownloadExceedsVPSKPI",
	"S93": "UploadL2WideWindowBand",
	"S94": "ConnectStreamLocalizeBottleneck",
	"S95": "HarnessDownloadCopy",
	"A4-1": "ArchA4P8",
	"A4-2": "ArchA4Acceptance",
	"A3-1": "ArchP1ProdDefault",
	"A7-2": "H2ConnectStreamTCPUploadServerBanner",
}

// l2StreamRelayGatePatterns maps A7/A8 stream/relay guards in go-test-masque-gates.ps1 S82 step.
var l2StreamRelayGatePatterns = map[string]string{
	"A7-1": "RelayTunnelPrimeBannerFlushesEarly",
	"A8-2": "DownloadPathAdapterSerializes",
}

func readRepoFile(t *testing.T, relPaths ...string) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	dir := wd
	for range 12 {
		for _, rel := range relPaths {
			path := filepath.Join(dir, rel)
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
	t.Fatalf("file not found: %v", relPaths)
	return ""
}

func readMasqueGateScript(t *testing.T) string {
	t.Helper()
	return readRepoFile(t,
		"scripts/go-test-masque-gates.ps1",
		filepath.Join("..", "scripts", "go-test-masque-gates.ps1"),
		filepath.Join("..", "..", "scripts", "go-test-masque-gates.ps1"),
	)
}

func readMasqueGateShell(t *testing.T) string {
	t.Helper()
	return readRepoFile(t,
		"scripts/go-test-masque-gates.sh",
		filepath.Join("..", "scripts", "go-test-masque-gates.sh"),
		filepath.Join("..", "..", "scripts", "go-test-masque-gates.sh"),
	)
}

func gateRunPattern(gateScript, gateLabel string) string {
	idx := strings.Index(gateScript, gateLabel)
	if idx < 0 {
		return ""
	}
	chunk := gateScript[idx:]
	if ps1 := strings.Index(chunk, `"-run", "`); ps1 >= 0 {
		rest := chunk[ps1+len(`"-run", "`):]
		if end := strings.Index(rest, `"`); end >= 0 {
			return rest[:end]
		}
	}
	start := strings.Index(chunk, "-run")
	if start < 0 {
		return ""
	}
	rest := chunk[start:]
	quote := `'`
	if strings.Contains(rest[:min(len(rest), 24)], `"`) {
		quote = `"`
	}
	qStart := strings.Index(rest, quote)
	if qStart < 0 {
		return ""
	}
	rest = rest[qStart+1:]
	qEnd := strings.Index(rest, quote)
	if qEnd < 0 {
		return ""
	}
	return rest[:qEnd]
}

func perfLocalizeCIRunPattern(ciYAML string) string {
	idx := strings.Index(ciYAML, "masque-perf-localize")
	if idx < 0 {
		return ""
	}
	return gateRunPattern(ciYAML[idx:], "-run")
}

// TestMasquePerfLocalizeGatePatternContract (S80): CI perf-localize -run must cover WriteTo anchors.
func TestMasquePerfLocalizeGatePatternContract(t *testing.T) {
	t.Parallel()
	ci := readRepoFile(t, ".github/workflows/ci.yml", filepath.Join("..", ".github", "workflows", "ci.yml"))
	pattern := perfLocalizeCIRunPattern(ci)
	if pattern == "" {
		t.Fatal("masque-perf-localize -run pattern not found in .github/workflows/ci.yml")
	}
	for _, anchor := range []string{"LocalizeBottleneck", "WriteQueueDepth", "LocalizeHarness"} {
		if !strings.Contains(pattern, anchor) {
			t.Errorf("perf localize CI pattern missing legacy anchor %q", anchor)
		}
	}
	for id, fragment := range perfLocalizeGatePatterns {
		if !strings.Contains(pattern, fragment) {
			t.Errorf("perf localize CI pattern missing %s (%q)", id, fragment)
		}
	}
}

// TestMasqueL2SynthGatePatternContract (S81): blocking PR gate must include L2 synth anchor in ps1 and sh.
func TestMasqueL2SynthGatePatternContract(t *testing.T) {
	t.Parallel()
	ps1 := readMasqueGateScript(t)
	sh := readMasqueGateShell(t)
	ps1Pattern := gateRunPattern(ps1, `Invoke-MasqueGate "L2 synth anchor"`)
	shPattern := gateRunPattern(sh, `invoke_masque_gate "L2 synth anchor"`)
	if ps1Pattern == "" {
		t.Fatal("L2 synth anchor -run pattern not found in go-test-masque-gates.ps1")
	}
	if shPattern == "" {
		t.Fatal("L2 synth anchor -run pattern not found in go-test-masque-gates.sh")
	}
	for id, fragment := range l2SynthGatePatterns {
		if !strings.Contains(ps1Pattern, fragment) {
			t.Errorf("L2 synth ps1 gate pattern missing %s (%q)", id, fragment)
		}
		if !strings.Contains(shPattern, fragment) {
			t.Errorf("L2 synth sh gate pattern missing %s (%q)", id, fragment)
		}
	}
	for _, anchor := range []string{"L2SynthGatePattern", "SimnetWindowedHarnessParity"} {
		if !strings.Contains(ps1Pattern, anchor) {
			t.Errorf("L2 synth ps1 gate pattern missing anchor %q", anchor)
		}
		if !strings.Contains(shPattern, anchor) {
			t.Errorf("L2 synth sh gate pattern missing anchor %q", anchor)
		}
	}

	streamPS1 := gateRunPattern(ps1, `Invoke-MasqueGate "L2 stream pkg relay`)
	streamSH := gateRunPattern(sh, `invoke_masque_gate "L2 stream pkg relay`)
	if streamPS1 == "" || streamSH == "" {
		t.Fatal("L2 stream pkg relay -run pattern not found in gate scripts")
	}
	for id, fragment := range l2StreamRelayGatePatterns {
		if !strings.Contains(streamPS1, fragment) {
			t.Errorf("L2 stream relay ps1 gate missing %s (%q)", id, fragment)
		}
		if !strings.Contains(streamSH, fragment) {
			t.Errorf("L2 stream relay sh gate missing %s (%q)", id, fragment)
		}
	}
}
