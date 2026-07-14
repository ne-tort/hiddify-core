//go:build masque_arch_ledger

package masque

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Arch investigation wave A1 — design-space score + pattern pick (synth contracts).

// TestArchA1PatternScore (A1-1): frozen P1–P6 (+P8) score matrix aligns with A0 RFC roles.
func TestArchA1PatternScore(t *testing.T) {
	if len(ArchPatternScoreTable) < 7 {
		t.Fatalf("A1-1 score table: %d rows want >= 7", len(ArchPatternScoreTable))
	}
	p1, ok := ArchPatternScoreFor(ArchPatternP1PipeUpload)
	if !ok || p1.Verdict != ArchVerdictPick || p1.KS1GainMbps < 21 {
		t.Fatalf("A1-1 P1 pick: %+v", p1)
	}
	p4, ok := ArchPatternScoreFor(ArchPatternP4ServerACK)
	if !ok || p4.Verdict != ArchVerdictReject || p4.KS1Verdict != "fail" {
		t.Fatalf("A1-1 P4 reject: %+v", p4)
	}
	p5, ok := ArchPatternScoreFor(ArchPatternP5DatagramACK)
	if !ok || p5.RFCScore != 0 || p5.Verdict != ArchVerdictReject {
		t.Fatalf("A1-1 P5 infeasible: %+v", p5)
	}
	for _, row := range ArchPatternScoreTable {
		if row.RFCScore < 0 || row.RFCScore > 3 {
			t.Fatalf("A1-1 RFC score out of range: %+v", row)
		}
		rfc, ok := ArchRFCConstraintFor(row.Pattern)
		if !ok {
			t.Fatalf("A1-1 missing A0 RFC row for %s", row.Pattern)
		}
		if !rfc.Feasible && row.RFCScore > 0 {
			t.Fatalf("A1-1 infeasible RFC must score 0: %+v", row)
		}
	}
	t.Logf("A1-1 pattern score: %d rows", len(ArchPatternScoreTable))
}

// TestArchA1P1SubVariants (A1-1a): prod pipe vs rollback vs misclassified near-misses.
func TestArchA1P1SubVariants(t *testing.T) {
	if len(ArchP1SubVariants) < 4 {
		t.Fatalf("A1-1a sub-variants: %d want >= 4", len(ArchP1SubVariants))
	}
	prod, ok := ArchP1SubVariantFor(ArchP1ProdPipe)
	if !ok || !prod.Valid || prod.ProdDefault {
		t.Fatalf("A1-1a prod pipe legacy opt-in: %+v", prod)
	}
	bidi, ok := ArchP1SubVariantFor(ArchP1BidiRollback)
	if !ok || !bidi.Valid || !bidi.ProdDefault {
		t.Fatalf("A1-1a bidi h3_stream prod default: %+v", bidi)
	}
	for _, id := range []ArchP1SubVariantID{ArchP1DualConnect, ArchP1WrongPlaneH3} {
		row, ok := ArchP1SubVariantFor(id)
		if !ok || row.Valid {
			t.Fatalf("A1-1a %s must be invalid P1 variant: %+v", id, row)
		}
	}
	t.Logf("A1-1a P1 sub-variants: prod=%s rollback env=%s", prod.ID, bidi.EnvRollback)
}

// TestArchA1ADR (A1-3): ADR doc exists and frozen pick matches ArchBidiDownloadADRDoc.
func TestArchA1ADR(t *testing.T) {
	adr := ArchBidiDownloadADRDoc
	if adr.Status != "accepted" || adr.DocPath == "" {
		t.Fatalf("A1-3 ADR contract: %+v", adr)
	}
	root := findHiddifyAppRoot(t)
	docPath := filepath.Join(root, adr.DocPath)
	if _, err := os.Stat(docPath); err != nil {
		t.Fatalf("A1-3 ADR missing at %s: %v", docPath, err)
	}
	body, err := os.ReadFile(docPath)
	if err != nil {
		t.Fatalf("A1-3 read ADR: %v", err)
	}
	text := string(body)
	for _, token := range []string{"P1", "P8", "P2", "pipe upload", "BulkStreamFCFloorBytes", adr.RollbackEnv} {
		if !strings.Contains(text, token) {
			t.Fatalf("A1-3 ADR missing token %q", token)
		}
	}
	if adr.Primary != ArchPrimaryPick || adr.Fallback != ArchFallbackPick || adr.Companion != ArchCompanionPick {
		t.Fatalf("A1-3 ADR pick mismatch: %+v", adr)
	}
	if adr.ProdDefaultPipe || adr.KS1TargetMbps != 21.0 {
		t.Fatalf("A1-3 ADR acceptance: ProdDefaultPipe must be false (h3_stream prod): %+v", adr)
	}
	t.Logf("A1-3 ADR: %s status=%s PRIMARY=%s COMPANION=%s FALLBACK=%s",
		adr.DocPath, adr.Status, adr.Primary, adr.Companion, adr.Fallback)
}

// TestArchA1PatternPick (A1-2): PRIMARY=P1, FALLBACK=P2, companion P8 bulk FC.
func TestArchA1PatternPick(t *testing.T) {
	p1, ok := ArchPatternScoreFor(ArchPrimaryPick)
	if !ok || p1.Verdict != ArchVerdictPick {
		t.Fatalf("A1-2 primary %s: %+v", ArchPrimaryPick, p1)
	}
	p2, ok := ArchPatternScoreFor(ArchFallbackPick)
	if !ok || p2.Verdict != ArchVerdictFallback {
		t.Fatalf("A1-2 fallback %s: %+v", ArchFallbackPick, p2)
	}
	p8, ok := ArchPatternScoreFor(ArchCompanionPick)
	if !ok || p8.Verdict != ArchVerdictBulkFC {
		t.Fatalf("A1-2 companion %s: %+v", ArchCompanionPick, p8)
	}
	if ArchPrimaryPick != ArchPatternP1PipeUpload || ArchFallbackPick != ArchPatternP2DualConnect {
		t.Fatalf("A1-2 pick constants: primary=%s fallback=%s", ArchPrimaryPick, ArchFallbackPick)
	}
	t.Logf("A1-2 pick: PRIMARY=%s FALLBACK=%s companion=%s", ArchPrimaryPick, ArchFallbackPick, ArchCompanionPick)
}

// TestArchA1P6ProductOnly (A1-7): P6 parallel CONNECT is product fan-out, not K-S1 fix.
func TestArchA1P6ProductOnly(t *testing.T) {
	if !ArchP6ProductOnlyScope() {
		t.Fatal("A1-7 P6 must be classified product-only")
	}
	p6, ok := ArchPatternScoreFor(ArchPatternP6Parallel)
	if !ok || p6.Verdict != ArchVerdictProductOnly {
		t.Fatalf("A1-7 P6 verdict: %+v", p6)
	}
	if p6.KS1Verdict != "n/a" {
		t.Fatalf("A1-7 P6 K-S1 verdict must be n/a (per-stream SUM, not single-leg): %+v", p6)
	}
	topo, ok := ArchTCPConnectTopologyFor(ArchPatternP6Parallel)
	if !ok || topo.CompositeOneConn {
		t.Fatalf("A1-7 P6 topology must expose N net.Conn to route: %+v", topo)
	}
	note, ok := ArchRouteScopeFor(ArchPatternP6Parallel)
	if !ok || note.InRouteScope {
		t.Fatalf("A1-7 P6 route scope: %+v", note)
	}
	t.Logf("A1-7 P6 product-only: SUM gain %.1f Mbit/s, single-leg n/a", p6.KS1GainMbps)
}

// TestArchA1RejectFramerOnly (A1-8): framer boost bounded reject for K-S1 (H5, guard A2-5).
func TestArchA1RejectFramerOnly(t *testing.T) {
	v := ArchFramerOnlyRejectVerdict
	if v.Verdict != "reject" || !v.SingleStream || v.MaxDeltaMbps != 2.0 {
		t.Fatalf("A1-8 framer reject verdict: %+v", v)
	}
	if v.GuardTest == "" || !strings.HasPrefix(v.GuardTest, "TestMasque") {
		t.Fatalf("A1-8 guard test: %q", v.GuardTest)
	}
	// Score table must not list framer-only as a pick (no phantom pattern row).
	for _, row := range ArchPatternScoreTable {
		if strings.Contains(strings.ToLower(row.Note), "framer") && row.Verdict == ArchVerdictPick {
			t.Fatalf("A1-8 framer must not be primary pick: %+v", row)
		}
	}
	t.Logf("A1-8 framer-only reject: Δ<%v Mbit/s on single stream, guard=%s", v.MaxDeltaMbps, v.GuardTest)
}
