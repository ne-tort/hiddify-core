package connectudp

import (
	"crypto/sha256"
	"encoding/hex"
)

// UDPProbeHeaderLen matches docker udp_sink_analyze.py HDR (seq u64 + run_id u32).
const UDPProbeHeaderLen = 12

// UDPProbeFillBytes returns zero-fill byte count for rxPkts at payloadLen (docker analyze parity).
func UDPProbeFillBytes(rxPkts int, payloadLen int) int {
	if rxPkts <= 0 || payloadLen < UDPProbeHeaderLen+1 {
		return 0
	}
	return (payloadLen - UDPProbeHeaderLen) * rxPkts
}

// ZeroCorpusSHA256 returns SHA256 of byteCount zero bytes (chunked 1 MiB, parity udp_sink_analyze.py).
func ZeroCorpusSHA256(byteCount int) string {
	if byteCount <= 0 {
		return hex.EncodeToString(sha256.New().Sum(nil))
	}
	const chunk = 1 << 20
	h := sha256.New()
	zeros := make([]byte, chunk)
	left := byteCount
	for left > 0 {
		n := left
		if n > chunk {
			n = chunk
		}
		h.Write(zeros[:n])
		left -= n
	}
	return hex.EncodeToString(h.Sum(nil))
}

// UDPProbeFillSHA256 returns expected fill_sha256 for paced probe analyze (rx pkts × zero tail).
func UDPProbeFillSHA256(rxPkts int, payloadLen int) string {
	return ZeroCorpusSHA256(UDPProbeFillBytes(rxPkts, payloadLen))
}
