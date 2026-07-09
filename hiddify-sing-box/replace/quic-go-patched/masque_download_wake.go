package quic

import "time"

// Prod CONNECT-stream download delivery wake anchors (parity with sing-box transport/masque/stream/sched).
const (
	masqueDownloadWakeMinBytes = 16 * 1024
	masqueDownloadWakeMaxBytes = 1024 * 1024
	masqueDownloadWakeBDPBytes = 64 * 1024
	masqueDownloadWakeBaseRTT  = 35 * time.Millisecond
)

// MasqueDownloadDeliveryWakeBatch returns RTT-scaled download wake batch (bytes), optionally clamped to peer send window.
func MasqueDownloadDeliveryWakeBatch(rtt time.Duration, availableSendBytes int) int {
	batch := masqueDownloadWakeBDPBytes
	if rtt > 0 {
		batch = int(int64(masqueDownloadWakeBDPBytes) * int64(rtt) / int64(masqueDownloadWakeBaseRTT))
	}
	batch = masqueClampDownloadWake(batch, availableSendBytes)
	return batch
}

func masqueClampDownloadWake(batch, availableSendBytes int) int {
	if batch < masqueDownloadWakeMinBytes {
		batch = masqueDownloadWakeMinBytes
	}
	if batch > masqueDownloadWakeMaxBytes {
		batch = masqueDownloadWakeMaxBytes
	}
	if availableSendBytes > 0 {
		cap := availableSendBytes / 2
		if cap < batch {
			batch = cap
		}
		if batch < masqueDownloadWakeMinBytes {
			batch = masqueDownloadWakeMinBytes
		}
		if batch > masqueDownloadWakeMaxBytes {
			batch = masqueDownloadWakeMaxBytes
		}
	}
	return batch
}
