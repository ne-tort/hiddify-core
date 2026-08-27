package testengine

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/ne-tort/pathology-core/compat/monitoring"
	"github.com/ne-tort/pathology-core/v2/config"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
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

func TestPingContextCancelsOnProbeCancel(t *testing.T) {
	probeCtx, probeCancel := context.WithCancel(context.Background())
	ctx, cancel := pingContext(context.Background(), probeCtx, time.Minute)
	defer cancel()
	probeCancel()
	select {
	case <-ctx.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("ping ctx should cancel when probeCtx is cancelled (Stop/idle)")
	}
}

func TestPingContextHonoursGrpcCancel(t *testing.T) {
	grpcCtx, grpcCancel := context.WithCancel(context.Background())
	probeCtx, probeCancel := context.WithCancel(context.Background())
	defer probeCancel()
	ctx, cancel := pingContext(grpcCtx, probeCtx, time.Minute)
	defer cancel()
	grpcCancel()
	select {
	case <-ctx.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("ping ctx should cancel when gRPC ctx is cancelled")
	}
}

func TestTakeServiceLockedCancelsProbes(t *testing.T) {
	e := &Engine{}
	e.mu.Lock()
	e.resetProbeCtxLocked()
	probe := e.probeCtx
	_ = e.takeServiceLocked()
	e.mu.Unlock()
	select {
	case <-probe.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("takeServiceLocked must cancel probeCtx")
	}
}

func TestPruneToAllowlist(t *testing.T) {
	opts := &option.Options{
		Outbounds: []option.Outbound{
			{
				Type: C.TypeSelector,
				Tag:  config.OutboundSelectTag,
				Options: &option.SelectorOutboundOptions{
					Outbounds: []string{"keep-a", "drop-b"},
				},
			},
			{Type: C.TypeDirect, Tag: config.OutboundDirectTag},
			{Type: C.TypeVLESS, Tag: "keep-a", Options: &option.VLESSOutboundOptions{}},
			{Type: C.TypeVLESS, Tag: "drop-b", Options: &option.VLESSOutboundOptions{}},
			{Type: C.TypeVLESS, Tag: "drop-c", Options: &option.VLESSOutboundOptions{}},
		},
		Endpoints: []option.Endpoint{
			{Type: C.TypeWireGuard, Tag: "ep-keep"},
			{Type: C.TypeWireGuard, Tag: "ep-drop"},
		},
	}
	narrowSelectOutbounds(opts, []string{"keep-a", "ep-keep"})
	pruneToAllowlist(opts, []string{"keep-a", "ep-keep"})

	tags := map[string]struct{}{}
	for _, ob := range opts.Outbounds {
		tags[ob.Tag] = struct{}{}
	}
	for _, want := range []string{config.OutboundSelectTag, config.OutboundDirectTag, "keep-a"} {
		if _, ok := tags[want]; !ok {
			t.Fatalf("missing outbound %q in %v", want, tags)
		}
	}
	for _, drop := range []string{"drop-b", "drop-c"} {
		if _, ok := tags[drop]; ok {
			t.Fatalf("outbound %q should be pruned", drop)
		}
	}
	if len(opts.Endpoints) != 1 || opts.Endpoints[0].Tag != "ep-keep" {
		t.Fatalf("endpoints=%v want [ep-keep]", opts.Endpoints)
	}
	sel := opts.Outbounds[0].Options.(*option.SelectorOutboundOptions)
	if len(sel.Outbounds) != 2 || sel.Outbounds[0] != "keep-a" || sel.Outbounds[1] != "ep-keep" {
		t.Fatalf("select members=%v", sel.Outbounds)
	}
}
