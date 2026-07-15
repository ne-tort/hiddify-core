package relay

import "time"

// RelayProbePolicy controls download prime on server relay (zero-env prod).
type RelayProbePolicy struct {
	// DownloadPrimeWait is extra wait after an instant peek for onward-TCP banner bytes.
	// Zero means peek-only: bulk copy starts immediately (WAN-friendly).
	DownloadPrimeWait time.Duration
}

// ProdRelayProbePolicy is the prod CONNECT-stream server probe policy.
func ProdRelayProbePolicy() RelayProbePolicy {
	return RelayProbePolicy{DownloadPrimeWait: 0}
}

func currentRelayProbePolicy() RelayProbePolicy {
	return ProdRelayProbePolicy()
}
