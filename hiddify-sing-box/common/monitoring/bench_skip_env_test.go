package monitoring

import "testing"

func TestBenchSkipURLTestEnv(t *testing.T) {
	t.Setenv(envBenchSkipURLTest, "")
	if BenchSkipURLTest() {
		t.Fatal("empty env must not skip")
	}
	t.Setenv(envBenchSkipURLTest, "1")
	if !BenchSkipURLTest() {
		t.Fatal("MASQUE_BENCH_SKIP_URL_TEST=1 must skip URL-test cycles")
	}
}
