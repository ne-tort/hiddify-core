package masque

// ArchPatternVerdict classifies A1 design-space pick outcome.
type ArchPatternVerdict string

const (
	ArchVerdictPick        ArchPatternVerdict = "pick"
	ArchVerdictFallback    ArchPatternVerdict = "fallback"
	ArchVerdictReject      ArchPatternVerdict = "reject"
	ArchVerdictProductOnly ArchPatternVerdict = "product-only"
	ArchVerdictBulkFC      ArchPatternVerdict = "bulk-fc"
	ArchVerdictFairness    ArchPatternVerdict = "fairness-only"
)

// ArchBlastRadius estimates implementation blast radius for a pattern (A1-1).
type ArchBlastRadius string

const (
	ArchBlastLow    ArchBlastRadius = "low"
	ArchBlastMedium ArchBlastRadius = "medium"
	ArchBlastHigh   ArchBlastRadius = "high"
)

// ArchPatternScoreRow scores RFC + peer + blast + K-S1 synth signal for one pattern (A1-1).
type ArchPatternScoreRow struct {
	Pattern      ArchPatternID
	RFCScore     int // 0–3 (3 = fully feasible on connect-stream)
	PeerScore    int // 0–3 (3 = prod-default peer acceptance)
	BlastRadius  ArchBlastRadius
	KS1GainMbps  float64 // observed synth ceiling or delta vs bidi ~15.7
	KS1Verdict   string  // pass | fail | n/a | companion
	Verdict      ArchPatternVerdict
	Note         string
}

// ArchPatternScoreTable is the frozen A1-1 score matrix (P1–P6 + P8 companion).
var ArchPatternScoreTable = []ArchPatternScoreRow{
	{
		Pattern: ArchPatternP1PipeUpload, RFCScore: 3, PeerScore: 3, BlastRadius: ArchBlastLow,
		KS1GainMbps: 234.2, KS1Verdict: "pass", Verdict: ArchVerdictPick,
		Note: "S89 pipe instant >21; windowed alone ~15.7 — needs P8 for prod K-S",
	},
	{
		Pattern: ArchPatternP2DualConnect, RFCScore: 3, PeerScore: 2, BlastRadius: ArchBlastMedium,
		KS1GainMbps: 21.0, KS1Verdict: "pass", Verdict: ArchVerdictFallback,
		Note: "2× CONNECT composite; separate stream IDs decouple upload ACK from download bulk",
	},
	{
		Pattern: ArchPatternP3CreditSched, RFCScore: 3, PeerScore: 3, BlastRadius: ArchBlastLow,
		KS1GainMbps: 0, KS1Verdict: "n/a", Verdict: ArchVerdictFairness,
		Note: "B8 band fairness only; does not lift single-leg K-S1 ceiling",
	},
	{
		Pattern: ArchPatternP4ServerACK, RFCScore: 3, PeerScore: 2, BlastRadius: ArchBlastHigh,
		KS1GainMbps: 14.9, KS1Verdict: "fail", Verdict: ArchVerdictReject,
		Note: "H-SRV-ACK16 server thin ACK — field ~14.9, client bidi unchanged",
	},
	{
		Pattern: ArchPatternP5DatagramACK, RFCScore: 0, PeerScore: 0, BlastRadius: ArchBlastHigh,
		KS1GainMbps: 0, KS1Verdict: "n/a", Verdict: ArchVerdictReject,
		Note: "RFC9298 connect-stream has no datagram ACK side channel",
	},
	{
		Pattern: ArchPatternP6Parallel, RFCScore: 3, PeerScore: 2, BlastRadius: ArchBlastMedium,
		KS1GainMbps: 62.9, KS1Verdict: "n/a", Verdict: ArchVerdictProductOnly,
		Note: "K-S4 SUM 62.9 = 4× per-stream ceiling; product fan-out, not single-leg K-S1",
	},
	{
		Pattern: ArchPatternP8BulkFC, RFCScore: 3, PeerScore: 3, BlastRadius: ArchBlastLow,
		KS1GainMbps: 62.9, KS1Verdict: "companion", Verdict: ArchVerdictBulkFC,
		Note: "L256 harness + simnet >52 with P1; prod FinalizeConnectStreamQUICConfig floor",
	},
}

// ArchPrimaryPick and ArchFallbackPick are the frozen A1-2 pattern selection.
const (
	ArchPrimaryPick   ArchPatternID = ArchPatternP1PipeUpload
	ArchFallbackPick  ArchPatternID = ArchPatternP2DualConnect
	ArchCompanionPick ArchPatternID = ArchPatternP8BulkFC
)

// ArchP1SubVariantID names P1 implementation shapes (A1-1a).
type ArchP1SubVariantID string

const (
	ArchP1ProdPipe       ArchP1SubVariantID = "prod_pipe"
	ArchP1BidiRollback   ArchP1SubVariantID = "bidi_rollback"
	ArchP1DualConnect    ArchP1SubVariantID = "dual_connect_p2"
	ArchP1WrongPlaneH3   ArchP1SubVariantID = "wrong_plane_h3_stream"
)

// ArchP1SubVariant documents P1 vs near-miss dial shapes (A1-1a).
type ArchP1SubVariant struct {
	ID          ArchP1SubVariantID
	Summary     string
	Valid       bool
	KS1Signal   string
	ProdDefault bool
	EnvRollback string
}

// ArchP1SubVariants is the frozen A1-1a sub-variant map.
var ArchP1SubVariants = []ArchP1SubVariant{
	{
		ID: ArchP1ProdPipe, Summary: "pipe upload on same CONNECT (UsesH3Stream=false)",
		Valid: true, KS1Signal: "instant 234; windowed ~15.7 alone; legacy opt-in only",
		ProdDefault: false, EnvRollback: "MASQUE_CONNECT_STREAM_PIPE_UPLOAD=1",
	},
	{
		ID: ArchP1BidiRollback, Summary: "coordinated bidi on one http3.Stream (duplex_coord)",
		Valid: true, KS1Signal: "prod default h3_stream; eager window unlocks K-S1/K-S2",
		ProdDefault: true, EnvRollback: "MASQUE_CONNECT_STREAM_PIPE_UPLOAD=1",
	},
	{
		ID: ArchP1DualConnect, Summary: "P2 fallback — not P1; 2× CONNECT composite",
		Valid: false, KS1Signal: "separate leg FC — classify as P2 not P1",
		ProdDefault: false, EnvRollback: "MASQUE_CONNECT_STREAM_DUAL_CONNECT=1",
	},
	{
		ID: ArchP1WrongPlaneH3, Summary: "H-AUTH-BIDI / authority h3 stream experiments",
		Valid: false, KS1Signal: "reject — wrong app plane on same wire stream",
		ProdDefault: false, EnvRollback: "MASQUE_CONNECT_AUTHORITY_BIDI_STREAM=1",
	},
}

// ArchFramerOnlyReject documents H5 bounded reject for K-S1 (A1-8, guard A2-5).
type ArchFramerOnlyReject struct {
	Hypothesis   string
	MaxDeltaMbps float64
	SingleStream bool
	Verdict      string
	GuardTest    string
}

// ArchFramerOnlyRejectVerdict is the frozen A1-8 reject note (framer boost ≠ architectural fix).
var ArchFramerOnlyRejectVerdict = ArchFramerOnlyReject{
	Hypothesis:   "QUIC framer bidi send boost alone lifts K-S1",
	MaxDeltaMbps: 2.0,
	SingleStream: true,
	Verdict:      "reject",
	GuardTest:    "TestMasqueDuplexSimnetBoostAB",
}

// ArchPatternScoreFor returns the A1-1 row for pattern, or false when unknown.
func ArchPatternScoreFor(id ArchPatternID) (ArchPatternScoreRow, bool) {
	for _, row := range ArchPatternScoreTable {
		if row.Pattern == id {
			return row, true
		}
	}
	return ArchPatternScoreRow{}, false
}

// ArchP1SubVariantFor returns the A1-1a row for id, or false when unknown.
func ArchP1SubVariantFor(id ArchP1SubVariantID) (ArchP1SubVariant, bool) {
	for _, row := range ArchP1SubVariants {
		if row.ID == id {
			return row, true
		}
	}
	return ArchP1SubVariant{}, false
}

// ArchP6ProductOnlyScope reports whether P6 is classified product-only (A1-7).
func ArchP6ProductOnlyScope() bool {
	row, ok := ArchPatternScoreFor(ArchPatternP6Parallel)
	return ok && row.Verdict == ArchVerdictProductOnly
}

// ArchBidiDownloadADR documents frozen A1-3 ADR metadata (docs/masque/ADR-bidi-download.md).
type ArchBidiDownloadADR struct {
	DocPath              string
	Status               string
	Primary              ArchPatternID
	Fallback             ArchPatternID
	Companion            ArchPatternID
	KS1AcceptancePattern string
	KS1TargetMbps        float64
	ProdDefaultPipe      bool
	RollbackEnv          string
	FallbackEnv          string
}

// ArchBidiDownloadADRDoc is the frozen A1-3 decision record cross-checked by TestArchA1ADR.
var ArchBidiDownloadADRDoc = ArchBidiDownloadADR{
	DocPath:              "docs/masque/ADR-bidi-download.md",
	Status:               "accepted",
	Primary:              ArchPrimaryPick,
	Fallback:             ArchFallbackPick,
	Companion:            ArchCompanionPick,
	KS1AcceptancePattern: "P8+P1",
	KS1TargetMbps:        21.0,
	ProdDefaultPipe:      false,
	RollbackEnv:          "MASQUE_CONNECT_STREAM_PIPE_UPLOAD=1",
	FallbackEnv:          "MASQUE_CONNECT_STREAM_DUAL_CONNECT=1",
}
