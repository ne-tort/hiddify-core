package masque

import (
	"fmt"
	"net"
	"testing"
	"time"
)

// refBenchDuration is the default REF synthetic benchmark window (matches GATE synth).
const refBenchDuration = connectStreamSynthProdBenchDuration

// refBenchResult is one REF or prod Mbps measurement for paired delta tests.
type refBenchResult struct {
	ID    string
	Shape string
	Leg   string
	Mbps  float64
	Bytes int64
}

// refProdPair compares a pure reference synth segment against our prod implementation.
type refProdPair struct {
	ID        string
	Shape     string
	Leg       string
	RefMbps   func(t *testing.T) float64
	ProdMbps  func(t *testing.T) float64
	RefFloor  float64
	ProdFloor float64
}

func assertRefProdDelta(t *testing.T, p refProdPair) refBenchResult {
	t.Helper()
	ref := p.RefMbps(t)
	prod := p.ProdMbps(t)
	gap := ref - prod
	t.Logf("REF-DELTA %s [%s/%s]: ref=%.1f prod=%.1f gap=%.1f (ref>=%.0f prod>=%.0f)",
		p.ID, p.Shape, p.Leg, ref, prod, gap, p.RefFloor, p.ProdFloor)
	if ref >= p.RefFloor && prod < p.ProdFloor {
		t.Fatalf("reference passes, prod fails — wrong pattern at %s: ref=%.1f prod=%.1f",
			p.ID, ref, prod)
	}
	return refBenchResult{ID: p.ID, Shape: p.Shape, Leg: p.Leg, Mbps: prod, Bytes: 0}
}

func logRefDeltaTable(t *testing.T, rows []refBenchResult, refRows []refBenchResult) {
	t.Helper()
	byID := map[string]refBenchResult{}
	for _, r := range refRows {
		byID[r.ID] = r
	}
	t.Log("REF-DELTA matrix (ref vs prod Mbps, gap):")
	for _, prod := range rows {
		ref := byID[prod.ID]
		gap := ref.Mbps - prod.Mbps
		t.Logf("  %-28s | ref=%7.1f | prod=%7.1f | gap=%+7.1f", prod.ID, ref.Mbps, prod.Mbps, gap)
	}
}

func measureRefConnDownloadMbps(conn net.Conn, duration time.Duration) (int64, float64, error) {
	return measureTCPDownloadWriteToMbps(conn, duration)
}

func measureRefConnUploadMbps(conn net.Conn, duration time.Duration) (int64, float64, error) {
	return measureTCPUploadMbps(conn, duration)
}

func measureRefConnDuplexMbps(conn net.Conn, duration time.Duration) (down, up, minLeg float64, err error) {
	return measureSegmentDuplexMbps(conn, duration)
}

func refDeltaDiagnosticFailMsg(id string, ref, prod, refFloor, prodFloor float64) string {
	return fmt.Sprintf("%s: ref=%.1f prod=%.1f (ref>=%.0f prod>=%.0f) — pattern divergence",
		id, ref, prod, refFloor, prodFloor)
}
