package monitoring

import (
	"os"
	"strings"
)

const envBenchSkipURLTest = "MASQUE_BENCH_SKIP_URL_TEST"

// BenchSkipURLTest reports whether outbound URL-test cycles should stay idle (MASQUE perf bench).
// Bench harness sets MASQUE_BENCH_SKIP_URL_TEST=1 so gstatic URL tests do not contend with
// CONNECT-stream iperf on the same bidi leg (false ~15 Mbit/s K-REF-B).
func BenchSkipURLTest() bool {
	return strings.TrimSpace(os.Getenv(envBenchSkipURLTest)) == "1"
}
