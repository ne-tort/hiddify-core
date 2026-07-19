package masque

import (
	"os"
	"strings"
	"testing"
)

// SkipUnlessMasqueBenchLong gates multi-leg burst binary-search / matrix sweeps / soak.
// Default `go test` must finish in seconds; set MASQUE_BENCH_LONG=1 for calibration.
func SkipUnlessMasqueBenchLong(t *testing.T) {
	t.Helper()
	skipUnlessMasqueBenchLong(t)
}

func skipUnlessMasqueBenchLong(t *testing.T) {
	t.Helper()
	v := strings.TrimSpace(os.Getenv("MASQUE_BENCH_LONG"))
	if v == "1" || strings.EqualFold(v, "true") {
		return
	}
	t.Skip("multi-leg bench/sweep; set MASQUE_BENCH_LONG=1")
}
