package connectip

// H2 / relay coalesce policy — single place for C2S vs S2C numbers.
//
// Docker A/B (2026-07-22) — C2S vis N after S2C ACK Flush KEEP:
//
//	N=4            — UP ~713 (ACK Flush alone)
//	N=8            — UP ~964
//	N=16 / 16KiB   — UP ~1140 / DOWN ~1290 (U/D≈0.88) KEEP
//	N=24           — UP ~1060 REGRESS vs 16
//	N=32           — historical Fountain-class death (pre ACK Flush)
//
// Pre-ACK-Flush cliff (N=8→216) was return-path ACK delay, not free proof that
// N>4 is forever unsafe. Relay S2C N=32 still OK via downloadCh+writeCh wake.

const (
	h2C2SVisMaxPkts  = 16
	h2C2SVisMaxBytes = 16 << 10

	h2RelayS2CBatchMaxPkts  = 32
	h2RelayS2CBatchMinBytes = 32 << 10
)

// H2C2SVisMaxPkts returns prod client C2S visibility packet cap.
func H2C2SVisMaxPkts() int { return h2C2SVisMaxPkts }

// H2C2SVisMaxBytes returns prod client C2S visibility byte cap.
func H2C2SVisMaxBytes() int { return h2C2SVisMaxBytes }

// H2RelayS2CBatchMaxPkts returns the relay downloadCh coalesce packet cap (doc mirror).
func H2RelayS2CBatchMaxPkts() int { return h2RelayS2CBatchMaxPkts }
