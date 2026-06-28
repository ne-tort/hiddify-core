package probe

import (
	"crypto/sha256"
	"encoding/hex"
)

// UDPProbeHeaderLen is the sequenced UDP sink header (seq u64 + run_id u32).
const UDPProbeHeaderLen = 12

// UDPProbeFillSHA256 returns the expected fill_sha256 for rxPkts zero-fill payloads
// (parity docker/masque-perf-lab bench/udp_sink_analyze.zero_corpus_hash).
func UDPProbeFillSHA256(rxPkts, payloadLen int) string {
	fillBytes := max(0, payloadLen-UDPProbeHeaderLen) * rxPkts
	h := sha256.New()
	const chunk = 1 << 20
	left := fillBytes
	for left > 0 {
		n := chunk
		if n > left {
			n = left
		}
		_, _ = h.Write(make([]byte, n))
		left -= n
	}
	return hex.EncodeToString(h.Sum(nil))
}
