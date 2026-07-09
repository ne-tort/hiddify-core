package sched

import "time"

// Shared CONNECT-stream wake anchors (MS3 client + MS4 server relay).
const (
	DownloadDeliveryWakeMinBytes = 16 * 1024
	DownloadDeliveryWakeMaxBytes = 1024 * 1024
	DownloadDeliveryWakeBDPBytes = 64 * 1024 // quic-go http3 wake batch parity
	DownloadDeliveryWakeBaseRTT  = 35 * time.Millisecond

	RelayDownloadPrimaryWakeBytes = 4 * 1024
	// HTTPS download: TLS ACKs during bulk S2C must not arm saturated duplex (~64KiB in <10s @10Mbit/s).
	RelayDuplexArmUploadBytes = 256 * 1024
	RelayTunnelUploadWakeBytes    = 128 * 1024
)

// DownloadDeliveryWakeBatch returns RTT-scaled consumer-paced download wake batch (bytes).
func DownloadDeliveryWakeBatch(rtt time.Duration) int {
	return DownloadDeliveryWakeBatchClamped(rtt, 0)
}

// DownloadDeliveryWakeBatchClamped returns RTT-scaled batch clamped to available C2S send window/2.
func DownloadDeliveryWakeBatchClamped(rtt time.Duration, availableSendBytes int) int {
	batch := DownloadDeliveryWakeBDPBytes
	if rtt > 0 {
		batch = int(int64(DownloadDeliveryWakeBDPBytes) * int64(rtt) / int64(DownloadDeliveryWakeBaseRTT))
	}
	batch = ClampBytes(batch, DownloadDeliveryWakeMinBytes, DownloadDeliveryWakeMaxBytes)
	if availableSendBytes > 0 {
		cap := availableSendBytes / 2
		if cap < batch {
			batch = cap
		}
		batch = ClampBytes(batch, DownloadDeliveryWakeMinBytes, DownloadDeliveryWakeMaxBytes)
	}
	return batch
}

// TheoreticalDownloadCeilingMbps estimates single-stream bidi FC ceiling (batch×8/RTT).
func TheoreticalDownloadCeilingMbps(batchBytes int, rtt time.Duration) float64 {
	if rtt <= 0 || batchBytes <= 0 {
		return 0
	}
	return float64(batchBytes*8) / rtt.Seconds() / 1e6
}

// ClampBytes limits v to [min, max].
func ClampBytes(v, min, max int) int {
	if v < min {
		return v + (min - v)
	}
	if v > max {
		return max
	}
	return v
}
