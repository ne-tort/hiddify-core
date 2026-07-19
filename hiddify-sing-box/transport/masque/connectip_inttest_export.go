package masque

// Inttest-facing exports (non-test .go). Test-only duplicates remain in export_test.go for masque_test.

import (
	"context"
	"net"
	"testing"
	"time"

	M "github.com/sagernet/sing/common/metadata"
)

// ConnectIPUploadBench is pipe/native upload Mbps for inttest gates.
type ConnectIPUploadBench struct {
	Layer string
	Mbps  float64
	Bytes int64
	Err   error
}

// ConnectIPSynthRegressionFloorUpMbps is the in-proc upload anti-regression floor (80 Mbit/s).
const ConnectIPSynthRegressionFloorUpMbps = connectIPSynthRegressionFloorUpMbps

// ConnectIPSynthProdMinMbps is the long-term per-leg synth target (1000 Mbit/s).
const ConnectIPSynthProdMinMbps = connectIPSynthProdMinMbps

// ConnectIPSynthMaxAsymRatio is the max allowed native up/down asymmetry ratio on GATE synth.
const ConnectIPSynthMaxAsymRatio = connectIPSynthMaxAsymRatio

// ConnectIPSynthRegressionFloorDownMbps returns the platform-native download regression floor.
func ConnectIPSynthRegressionFloorDownMbps() float64 {
	return connectIPNativeSynthRegressionFloorDownMbps()
}

// ConnectIPSynthPipeMinRatio is the native/pipe L1 upload ratio floor for synth gates.
const ConnectIPSynthPipeMinRatio = connectIPSynthPipeMinRatio

// ConnectIPSynthPipeFastMinMbps is the pipe L1 threshold for fast-pipe native/pipe checks.
const ConnectIPSynthPipeFastMinMbps = connectIPSynthPipeFastMinMbps

// ConnectIPSynthPipeFastFloorRatio is the hard fail native/pipe ratio when pipe is fast.
const ConnectIPSynthPipeFastFloorRatio = connectIPSynthPipeFastFloorRatio

// ConnectIPSynthPipeFastTargetRatio is the OPEN target native/pipe ratio when pipe is fast.
const ConnectIPSynthPipeFastTargetRatio = connectIPSynthPipeFastTargetRatio

// ConnectIPSynthWakeEstSegmentBytes is the estimated native upload segment size for wake coalesce tests.
const ConnectIPSynthWakeEstSegmentBytes = connectIPSynthWakeEstSegmentBytes

// LocalizeBenchDuration is the shared in-proc localize bench window (400ms).
const LocalizeBenchDuration = localizeBenchDuration

func connectIPUploadBenchFromResult(r connectIPUploadBenchResult) ConnectIPUploadBench {
	return ConnectIPUploadBench{Layer: r.layer, Mbps: r.mbps, Bytes: r.bytes, Err: r.err}
}

// BenchConnectIPUploadInstantL1 runs prod-shaped instant pipe upload (L1-prod, best-of-3).
func BenchConnectIPUploadInstantL1(t *testing.T, duration time.Duration) ConnectIPUploadBench {
	t.Helper()
	return connectIPUploadBenchFromResult(benchConnectIPUploadLayerBest(t, "L1-prod", prodInstantPacketLink{}, duration, 3))
}

// ConnectIPUploadNativeHint localizes native vs pipe L1 upload gap.
func ConnectIPUploadNativeHint(pipeL1Mbps, nativeMbps float64) string {
	return connectIPUploadNativeLayerHint(pipeL1Mbps, nativeMbps)
}

// InttestMarkConnectIPServerRecycled marks CONNECT-IP plane stale after test server restart (W-IP-ARCH-3).
func InttestMarkConnectIPServerRecycled(sess ClientSession) {
	if r, ok := sess.(interface{ MarkConnectIPServerRecycled() }); ok {
		r.MarkConnectIPServerRecycled()
	}
}

// InttestConnectIPServerGenerationStale reports the explicit server-recycle latch (LIFE-1 / P1-4).
func InttestConnectIPServerGenerationStale(sess ClientSession) bool {
	if r, ok := sess.(interface{ ConnectIPServerGenerationStale() bool }); ok {
		return r.ConnectIPServerGenerationStale()
	}
	return false
}

// InttestReopenConnectIPNativeL3Plane resets datagram plane and rebinds tun L3 bridge (W-IP-ARCH-3).
func InttestReopenConnectIPNativeL3Plane(ctx context.Context, sess ClientSession) error {
	if r, ok := sess.(interface {
		ReopenConnectIPNativeL3Plane(context.Context) error
	}); ok {
		return r.ReopenConnectIPNativeL3Plane(ctx)
	}
	return nil
}

// InttestResetConnectIPTCPNetstack resets cached TCP netstack between CM probe and bulk (synth only).
func InttestResetConnectIPTCPNetstack(sess ClientSession) {
	if r, ok := sess.(interface{ ResetConnectIPTCPAfterShortRelay() }); ok {
		r.ResetConnectIPTCPAfterShortRelay()
	}
}

// InttestWaitConnectIPNativeL3PlaneReady blocks until native L3 ingress is active.
func InttestWaitConnectIPNativeL3PlaneReady(ctx context.Context, sess ClientSession) error {
	if w, ok := sess.(interface {
		WaitConnectIPNativeL3PlaneReady(context.Context) error
	}); ok {
		return w.WaitConnectIPNativeL3PlaneReady(ctx)
	}
	return nil
}

// InttestDialNativeL3TCP dials via connectip netstack on native L3 plane (usque path).
func InttestDialNativeL3TCP(ctx context.Context, sess ClientSession, dest M.Socksaddr) (net.Conn, error) {
	return DialNativeL3TCP(ctx, sess, dest)
}

// InttestWarmConnectIPTCPAfterShortRelay primes TCP ingress after CM nc probe (synth/prod hook).
func InttestWarmConnectIPTCPAfterShortRelay(ctx context.Context, sess ClientSession, dest M.Socksaddr) {
	if w, ok := sess.(interface {
		WarmConnectIPTCPAfterShortRelay(context.Context, M.Socksaddr)
	}); ok {
		w.WarmConnectIPTCPAfterShortRelay(ctx, dest)
	}
}
