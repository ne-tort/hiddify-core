package masque

// Scaling-map gate: where multi-flow stops scaling, why (intra vs multi-session), and
// what is normal shared-resource ceiling vs a bug worth fixing.

import (
	"fmt"
	"net"
	"net/http"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/sagernet/sing-box/transport/masque/connectudp"
)

const (
	// Soft vs hard efficiency bands (agg / (single * N)).
	connectUDPScaleEffLinear     = 0.75
	connectUDPScaleEffSoftFloor  = 0.35
	connectUDPScaleEffN2BugFloor = 0.50 // N=2 must nearly double; below → fan-out bug
	connectUDPScaleSymN2BugFloor = 0.45
)

type connectUDPScaleClass string

const (
	scaleClassLinear      connectUDPScaleClass = "linear"
	scaleClassSoftCeiling connectUDPScaleClass = "soft_ceiling"
	scaleClassHardCeiling connectUDPScaleClass = "hard_ceiling"
)

type connectUDPScalePoint struct {
	N         int
	AggMbps   float64
	Eff       float64
	Sym       float64
	PerStream []float64
	Class     connectUDPScaleClass
	DigHint   string
}

func classifyConnectUDPScaleEff(n int, eff float64) (connectUDPScaleClass, string) {
	switch {
	case eff >= connectUDPScaleEffLinear:
		return scaleClassLinear, "near-linear — keep; not a ceiling yet"
	case eff >= connectUDPScaleEffSoftFloor:
		return scaleClassSoftCeiling,
			"sublinear shared resource (QUIC mux / H2 TCP / CPU) — normal; dig only if product needs >N concurrent bulk uploads"
	default:
		hint := "collapse vs single×N — check symmetry, desktop scheduler, or true fan-out bug"
		if n >= 4 && (runtime.GOOS == "windows" || runtime.GOOS == "darwin") {
			hint = "hard ceiling on desktop often host QUIC/TCP scheduling — Linux Docker is reference before code dig"
		}
		return scaleClassHardCeiling, hint
	}
}

// gateConnectUDPScalingMap sweeps N=1,2,4,8 (intra-session), classifies each point, and at N=4
// contrasts multi-session for mux vs server attribution.
//
// Fail hard only on N=2 regression (should scale); soft/hard ceiling at N≥4 is logged as
// STOP_DIGGING / OPEN, not an automatic fail.
func gateConnectUDPScalingMap(t *testing.T, layer string) {
	t.Helper()
	dur := connectUDPSynthProdBenchDuration
	if layer == "h3" {
		dur = 3 * time.Second
	}
	payloadLen := connectudp.DefaultBenchUDPPayloadLen
	counts := []int{1, 2, 4, 8}

	sink, _ := runUDPSink(t, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	sinkAddr := sink.LocalAddr().(*net.UDPAddr)

	var proxyPort int
	switch layer {
	case "h2":
		proxyPort = startInProcessH2UDPConnectProxy(t)
	case "h3":
		proxyPort = startInProcessMasqueUDPProxy(t, func(mux *http.ServeMux, p int) {
			registerMasqueUDPProxyHandler(t, mux, p)
		})
	default:
		t.Fatalf("unknown layer %q", layer)
	}

	points := make([]connectUDPScalePoint, 0, len(counts))
	var singleMbps float64
	for _, n := range counts {
		legDur := dur
		if layer == "h3" && n >= 4 {
			legDur = 4 * time.Second
		}
		agg, per, sym := benchParallelConnectUDPStreams(t, layer, proxyPort, sinkAddr, n, legDur, payloadLen)
		if n == 1 && len(per) > 0 {
			singleMbps = per[0]
		}
		eff := 0.0
		if singleMbps > 0 {
			eff = agg / (singleMbps * float64(n))
		}
		class, hint := classifyConnectUDPScaleEff(n, eff)
		pt := connectUDPScalePoint{
			N: n, AggMbps: agg, Eff: eff, Sym: sym, PerStream: per, Class: class, DigHint: hint,
		}
		points = append(points, pt)
		t.Logf("SCALE_MAP %s N=%d: agg=%.1f eff=%.2f sym=%.2f class=%s per=[%s]",
			layer, n, agg, eff, sym, class, formatStreamMbps(per, legDur))
		t.Logf("  dig: %s", hint)
	}

	// N=2 must still scale — collapse here is a bug, not "normal ceiling".
	var n2 *connectUDPScalePoint
	for i := range points {
		if points[i].N == 2 {
			n2 = &points[i]
			break
		}
	}
	if n2 != nil {
		if n2.Eff < connectUDPScaleEffN2BugFloor {
			t.Fatalf("%s scale map N=2 eff=%.2f < %.2f (fan-out bug, not shared ceiling)",
				layer, n2.Eff, connectUDPScaleEffN2BugFloor)
		}
		if n2.Sym < connectUDPScaleSymN2BugFloor {
			t.Fatalf("%s scale map N=2 sym=%.2f < %.2f (uneven fan-out)", layer, n2.Sym, connectUDPScaleSymN2BugFloor)
		}
	}

	// Attribution at N=4: intra vs multi-session.
	attrN := 4
	attrDur := dur
	if layer == "h3" {
		attrDur = 4 * time.Second
	}
	intraAgg, _, _ := benchParallelConnectUDPStreams(t, layer, proxyPort, sinkAddr, attrN, attrDur, payloadLen)
	multiAgg, multiPer, multiSym := benchParallelConnectUDPMultiSession(t, layer, proxyPort, sinkAddr, attrN, attrDur, payloadLen)
	multiRatio := 0.0
	if intraAgg > 0 {
		multiRatio = multiAgg / intraAgg
	}
	attrVerdict := "mixed"
	attrHint := "profile on Linux Docker if product needs more aggregate"
	switch {
	case multiRatio >= 1.35:
		attrVerdict = "quic_or_h2_mux_ceiling"
		attrHint = "multi-session >> intra — shared connection mux; separate sessions help bulk, not a relay bug"
	case multiRatio <= 1.10:
		attrVerdict = "server_or_host_ceiling"
		attrHint = "multi ~ intra — shared server/relay/CPU/host; more client sessions won't fix"
	}
	t.Logf("SCALE_MAP %s attribution x%d: intra=%.1f multi=%.1f multi/intra=%.2f multi_sym=%.2f per=[%s]",
		layer, attrN, intraAgg, multiAgg, multiRatio, multiSym, formatStreamMbps(multiPer, attrDur))
	t.Logf("  attribution=%s — %s", attrVerdict, attrHint)

	onset := firstSoftOrHardOnset(points)
	var b strings.Builder
	fmt.Fprintf(&b, "SCALE_MAP_VERDICT %s single=%.1f onset_N=%s attr=%s |", layer, singleMbps, onset, attrVerdict)
	for _, p := range points {
		fmt.Fprintf(&b, " N%d:%s(eff=%.2f)", p.N, p.Class, p.Eff)
	}
	t.Log(b.String())
	if onset != "none" {
		t.Logf("STOP_DIGGING: first non-linear at %s is expected shared-resource scaling for bulk max-speed-via-streams; "+
			"fix only if N=2 fails or product requires linear bulk beyond onset", onset)
	}
}

func firstSoftOrHardOnset(points []connectUDPScalePoint) string {
	for _, p := range points {
		if p.N <= 1 {
			continue
		}
		if p.Class == scaleClassSoftCeiling || p.Class == scaleClassHardCeiling {
			return fmt.Sprintf("N=%d(%s)", p.N, p.Class)
		}
	}
	return "none"
}
