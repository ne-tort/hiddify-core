package testengine

import (
	"fmt"
	"testing"
	"time"

	"github.com/ne-tort/pathology-core/compat/monitoring"
)

func TestNormalizeStrategy(t *testing.T) {
	cases := map[string]string{
		"":             "single",
		"single":       "single",
		"fastAverage":  "fastAverage",
		"fast_average": "fastAverage",
		"stress":       "stress",
		"STRESS":       "stress",
	}
	for in, want := range cases {
		if got := normalizeStrategy(in); got != want {
			t.Fatalf("normalizeStrategy(%q)=%q want %q", in, got, want)
		}
	}
}

func TestSanitizeProfileID(t *testing.T) {
	if got := sanitizeProfileID("ab/c.."); got != "ab_c__" {
		t.Fatalf("got %q", got)
	}
	if got := sanitizeProfileID(""); got != "profile" {
		t.Fatalf("empty got %q", got)
	}
}

func TestStrategyParams(t *testing.T) {
	s, c := strategyParams("single")
	if s != 1 || c != 8 {
		t.Fatalf("single=%d,%d", s, c)
	}
	s, c = strategyParams("fastAverage")
	if s != 3 || c != 8 {
		t.Fatalf("avg=%d,%d", s, c)
	}
	s, c = strategyParams("stress")
	if s != 10 || c != 4 {
		t.Fatalf("stress=%d,%d", s, c)
	}
}

func TestContainsString(t *testing.T) {
	if !containsString([]string{"a", "b"}, "b") {
		t.Fatal("expected hit")
	}
	if containsString([]string{"a"}, "z") {
		t.Fatal("expected miss")
	}
}

func TestIsBindError(t *testing.T) {
	if !isBindError(fmt.Errorf("listen tcp 127.0.0.1:1: bind: address already in use")) {
		t.Fatal("expected bind error")
	}
	if isBindError(fmt.Errorf("dns bind lookup failed")) {
		t.Fatal("false positive on bare 'bind'")
	}
}

func TestProbeWallClock(t *testing.T) {
	d := probeWallClock(8, 1, 8)
	if d < monitoring.ProbeTimeout+time.Second {
		t.Fatalf("too short: %v", d)
	}
	d2 := probeWallClock(8, 1, 4)
	if d2 <= d {
		t.Fatalf("more rounds should need more wall clock: %v vs %v", d2, d)
	}
	stress := probeMaxWait(10)
	if stress < monitoring.ProbeTimeout*10 {
		t.Fatalf("stress maxWait too short: %v", stress)
	}
}

func TestIntersectAllowlist(t *testing.T) {
	got := intersectAllowlist([]string{"a", "b", "c"}, []string{"c", "a", "z"})
	if len(got) != 2 || got[0] != "a" || got[1] != "c" {
		t.Fatalf("order from allowlist: %v", got)
	}
	if intersectAllowlist(nil, []string{"a"}) != nil {
		t.Fatal("empty allowlist")
	}
}

func TestNormalizeAllowlist(t *testing.T) {
	got := normalizeAllowlist([]string{" a ", "", "a", "b"})
	if len(got) != 2 || got[0] != "a" || got[1] != "b" {
		t.Fatalf("%v", got)
	}
}

func TestFailFastLimit(t *testing.T) {
	if failFastLimit(1) != 1 || failFastLimit(10) != 1 {
		t.Fatalf("dead-leaf fail-fast should be 1, got %d/%d", failFastLimit(1), failFastLimit(10))
	}
}
