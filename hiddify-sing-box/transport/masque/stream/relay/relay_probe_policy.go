package relay

import "time"

// RelayProbePolicy controls non-blocking upload probe and download prime on server relay (MS4 — zero-env).
type RelayProbePolicy struct {
	// DownloadPrimeWait is extra wait after an instant peek for onward-TCP banner bytes.
	// Zero means peek-only: bulk copy starts immediately (WAN-friendly).
	DownloadPrimeWait time.Duration
	// UploadProbeWait is extra wait after an instant peek on the upload leg.
	// Zero means peek-only: classify download-primary only on immediate EOF/byte.
	UploadProbeWait time.Duration
}

// ProdRelayProbePolicy is the prod CONNECT-stream server probe policy.
func ProdRelayProbePolicy() RelayProbePolicy {
	return RelayProbePolicy{
		DownloadPrimeWait: 0,
		UploadProbeWait:   0,
	}
}

// LegacyRelayProbePolicy retains colo-shaped waits for regression harnesses.
func LegacyRelayProbePolicy() RelayProbePolicy {
	return RelayProbePolicy{
		DownloadPrimeWait: 250 * time.Millisecond,
		UploadProbeWait:   3 * time.Millisecond,
	}
}

func currentRelayProbePolicy() RelayProbePolicy {
	return ProdRelayProbePolicy()
}
