package connectudp_test

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sagernet/sing-box/transport/masque/connectudp"
)

const connectUDPPathMaxLOC = 900

// TestConnectUDPPathPackageLOCGate locks W-UDP-1 path package size (max single non-test file ≤ 900 LOC).
func TestConnectUDPPathPackageLOCGate(t *testing.T) {
	t.Parallel()
	var worst struct {
		path string
		loc  int
	}
	err := filepath.WalkDir(".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		loc := 0
		for _, line := range strings.Split(string(b), "\n") {
			trim := strings.TrimSpace(line)
			if trim == "" || strings.HasPrefix(trim, "//") {
				continue
			}
			loc++
		}
		if loc > worst.loc {
			worst.path = path
			worst.loc = loc
		}
		if loc > connectUDPPathMaxLOC {
			t.Fatalf("%s: %d LOC exceeds gate %d", path, loc, connectUDPPathMaxLOC)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk connectudp tree: %v", err)
	}
	t.Logf("connectudp path LOC gate ok (largest %s %d LOC, max %d)", worst.path, worst.loc, connectUDPPathMaxLOC)
}

func TestDefaultBenchUDPPayloadLen(t *testing.T) {
	if connectudp.DefaultBenchUDPPayloadLen != 512 {
		t.Fatalf("DefaultBenchUDPPayloadLen=%d want 512", connectudp.DefaultBenchUDPPayloadLen)
	}
}

func TestPaceIntervalZeroTarget(t *testing.T) {
	if got := connectudp.PaceInterval(connectudp.DefaultBenchUDPPayloadLen, 0); got != 0 {
		t.Fatalf("PaceInterval burst=%v want 0", got)
	}
}

func TestPaceSleepUntilCompensatesSendLatency(t *testing.T) {
	const targetMbit = 8.0
	payloadLen := connectudp.DefaultBenchUDPPayloadLen
	interval := connectudp.PaceInterval(payloadLen, targetMbit)
	sendCost := interval / 2

	var slot time.Time
	start := time.Now()
	for range 20 {
		connectudp.PaceSleepUntil(&slot, payloadLen, targetMbit)
		time.Sleep(sendCost)
	}
	elapsed := time.Since(start)
	want := 20 * interval
	tol := interval // scheduler jitter on Windows
	if d := elapsed - want; d < -tol || d > tol {
		t.Fatalf("compensated pacing elapsed=%v want ~%v (tol %v)", elapsed, want, tol)
	}
}
