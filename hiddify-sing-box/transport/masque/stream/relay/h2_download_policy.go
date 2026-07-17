package relay

import (
	"sync/atomic"
	"time"
)

// H2DownloadPolicy controls onward TCP → H2 DATA coalesce on the server download leg.
type H2DownloadPolicy struct {
	BufferBytes   int
	FillWait      time.Duration
	FlushMinBytes int
	FillMaxWall   time.Duration
}

var h2DownloadPolicy atomic.Pointer[H2DownloadPolicy]

func defaultH2DownloadPolicy() H2DownloadPolicy {
	return H2DownloadPolicy{
		BufferBytes:   RelayTunnelBufLen,
		FillWait:      h2DownloadFillWait,
		FlushMinBytes: h2DownloadFlushMinBytes,
		FillMaxWall:   h2DownloadFillMaxWall,
	}
}

// ApplyH2DownloadPolicy installs server download-relay coalesce (from h2_tuning).
// Zero fields fall back to baked defaults. Process-wide: last server endpoint wins.
func ApplyH2DownloadPolicy(p H2DownloadPolicy) {
	d := defaultH2DownloadPolicy()
	if p.BufferBytes > 0 {
		d.BufferBytes = p.BufferBytes
	}
	if p.FillWait > 0 {
		d.FillWait = p.FillWait
	}
	if p.FlushMinBytes > 0 {
		d.FlushMinBytes = p.FlushMinBytes
	}
	if p.FillMaxWall > 0 {
		d.FillMaxWall = p.FillMaxWall
	}
	cp := d
	h2DownloadPolicy.Store(&cp)
}

func currentH2DownloadPolicy() H2DownloadPolicy {
	if p := h2DownloadPolicy.Load(); p != nil {
		return *p
	}
	return defaultH2DownloadPolicy()
}
