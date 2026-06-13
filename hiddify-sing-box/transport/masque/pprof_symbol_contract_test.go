package masque

import (
	"bytes"
	"path/filepath"
	"runtime/pprof"
	"strings"
	"testing"

	"github.com/google/pprof/profile"
)

// masquePprofHotspotSymbols lists substrings that must appear in CPU profiles during
// CONNECT-stream WriteTo download (S48 nightly cpuprofile contract).
// Server relay may run off-thread — anchor on client download stack only.
var masquePprofHotspotSymbols = []string{
	"WriteTo",
	"TunnelConn",
}

// masquePprofDrainHotspotSymbols — prod WriteTo uses either io.CopyBuffer or duplex coord drain.
var masquePprofDrainHotspotSymbols = []string{
	"CopyBuffer",
	"writeH3DownloadTo",
	"interleaveDuplexTransfer",
}

// masqueNightlyCpuprofileSelector is the -run fragment for nightly CONNECT-stream WriteTo cpuprofile (S88).
const masqueNightlyCpuprofileSelector = "NightlyCpuprofileWriteTo"

// pprofGatePatterns maps SYNTH-TEST-PLAN P2 CPU/pprof IDs to gate -run fragments.
var pprofGatePatterns = map[string]string{
	"S18":  "ConnectStreamDownloadLayer",
	"S19":  "ConnectStreamCPUBudget",
	"S48":  "PprofSymbol",
	"S84":  "WindowedBidiConnThroughput",
	"S85":  "RelayTCPTunnelDownloadPaths",
	"S86":  "ConnectStreamH2EndToEndDownload",
	"S88":  masqueNightlyCpuprofileSelector,
}

func captureCPUProfile(fn func()) (*profile.Profile, error) {
	var buf bytes.Buffer
	if err := pprof.StartCPUProfile(&buf); err != nil {
		return nil, err
	}
	fn()
	pprof.StopCPUProfile()
	return profile.Parse(&buf)
}

func profileContainsSymbol(prof *profile.Profile, substr string) bool {
	for _, loc := range prof.Location {
		for _, line := range loc.Line {
			if line.Function == nil {
				continue
			}
			if strings.Contains(line.Function.Name, substr) {
				return true
			}
		}
	}
	return false
}

// TestMasquePprofSymbolContract (S48): CONNECT-stream WriteTo download profile must include
// prod hotspot symbols so nightly cpuprofile diffs stay anchored.
func TestMasquePprofSymbolContract(t *testing.T) {
	pool := startConnectStreamParallelPool(t, instantBidiLink{})
	defer pool.close()

	prof, err := captureCPUProfile(func() {
		for range 12 {
			n, err := pool.drainDownloadWriteToOnce(connectStreamDownloadBenchBytes / 2)
			if err != nil {
				panic(err)
			}
			if n < connectStreamDownloadBenchBytes/2 {
				panic("short profile drain")
			}
		}
	})
	if err != nil {
		t.Fatalf("capture profile: %v", err)
	}
	if len(prof.Sample) == 0 {
		t.Fatal("CPU profile has no samples")
	}
	for _, sym := range masquePprofHotspotSymbols {
		if !profileContainsSymbol(prof, sym) {
			t.Errorf("CPU profile missing hotspot symbol %q", sym)
		}
	}
	drainFound := false
	for _, sym := range masquePprofDrainHotspotSymbols {
		if profileContainsSymbol(prof, sym) {
			drainFound = true
			break
		}
	}
	if !drainFound {
		t.Errorf("CPU profile missing drain hotspot (want one of %v)", masquePprofDrainHotspotSymbols)
	}
}

// TestMasquePprofSymbolGatePatternContract (S48): L2 synth gate must include CPU/pprof bench anchors.
func TestMasquePprofSymbolGatePatternContract(t *testing.T) {
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
	for id, fragment := range pprofGatePatterns {
		if !strings.Contains(ps1Pattern, fragment) {
			t.Errorf("L2 synth ps1 gate pattern missing %s (%q)", id, fragment)
		}
		if !strings.Contains(shPattern, fragment) {
			t.Errorf("L2 synth sh gate pattern missing %s (%q)", id, fragment)
		}
	}
}

// TestMasqueNightlyCpuprofileWriteTo (S20/S88): workload for nightly go test -cpuprofile.
// Run: go test ./transport/masque -run NightlyCpuprofileWriteTo -cpuprofile=masque-connect-stream-writeto.prof
func TestMasqueNightlyCpuprofileWriteTo(t *testing.T) {
	if testing.Short() {
		t.Skip("nightly cpuprofile workload")
	}
	pool := startConnectStreamParallelPool(t, instantBidiLink{})
	defer pool.close()
	for range 24 {
		n, err := pool.drainDownloadWriteToOnce(connectStreamDownloadBenchBytes / 2)
		if err != nil {
			t.Fatalf("nightly WriteTo drain: %v", err)
		}
		if n < connectStreamDownloadBenchBytes/2 {
			t.Fatalf("short nightly drain: %d", n)
		}
	}
}

func nightlyCpuprofileCIChunk(ciYAML string) string {
	idx := strings.Index(ciYAML, "masque-nightly-perf")
	if idx < 0 {
		return ""
	}
	return ciYAML[idx:]
}

// TestMasqueNightlyCpuprofileArtifactContract (S20): nightly job must emit -cpuprofile artifact.
func TestMasqueNightlyCpuprofileArtifactContract(t *testing.T) {
	t.Parallel()
	ci := readRepoFile(t, ".github/workflows/ci.yml", filepath.Join("..", ".github", "workflows", "ci.yml"))
	chunk := nightlyCpuprofileCIChunk(ci)
	if chunk == "" {
		t.Fatal("masque-nightly-perf job not found in .github/workflows/ci.yml")
	}
	if !strings.Contains(chunk, "-cpuprofile=") {
		t.Fatal("masque-nightly-perf missing -cpuprofile artifact path")
	}
	if !strings.Contains(chunk, "upload-artifact") || !strings.Contains(chunk, "cpuprofile") {
		t.Fatal("masque-nightly-perf missing cpuprofile artifact upload step")
	}
}

// TestMasqueNightlyCpuprofileWriteToSelectorContract (S88): nightly -run must anchor WriteTo workload.
func TestMasqueNightlyCpuprofileWriteToSelectorContract(t *testing.T) {
	t.Parallel()
	ci := readRepoFile(t, ".github/workflows/ci.yml", filepath.Join("..", ".github", "workflows", "ci.yml"))
	chunk := nightlyCpuprofileCIChunk(ci)
	if chunk == "" {
		t.Fatal("masque-nightly-perf job not found in .github/workflows/ci.yml")
	}
	pattern := gateRunPattern(chunk, "-run")
	if pattern == "" {
		t.Fatal("masque-nightly-perf -run pattern not found in .github/workflows/ci.yml")
	}
	if !strings.Contains(pattern, masqueNightlyCpuprofileSelector) {
		t.Fatalf("nightly cpuprofile -run missing WriteTo selector %q", masqueNightlyCpuprofileSelector)
	}
}
