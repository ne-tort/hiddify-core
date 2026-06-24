package h2

import "net/http"

// LegProfile selects CONNECT-UDP hot-path shape per stream role (W-UDP-2t).
type LegProfile uint8

const (
	// LegProfileUpload: asymmetric C2S leg — thin upload, no downlink pump.
	LegProfileUpload LegProfile = iota
	// LegProfileDownloadFountain: S2C receive / fountain — blocking read, bulk server flush.
	LegProfileDownloadFountain
	// LegProfileEchoBidi: full-duplex bidi — pump, coalesce, interactive read-wake.
	LegProfileEchoBidi
)

func legProfileForStreamRole(role streamRole) LegProfile {
	switch role {
	case streamRoleUpload:
		return LegProfileUpload
	case streamRoleDownload:
		return LegProfileDownloadFountain
	default:
		return LegProfileEchoBidi
	}
}

func (p LegProfile) uploadImmediateFlush() bool {
	return p == LegProfileUpload
}

// uploadNoCoalesceTimer disables debounced upload flush; bulk still coalesces synchronously.
func (p LegProfile) uploadNoCoalesceTimer() bool {
	return p == LegProfileUpload
}

func (p LegProfile) uploadCoalesceEnabled() bool {
	return p == LegProfileEchoBidi
}

func (p LegProfile) usesAsyncDownlinkPump() bool {
	return p == LegProfileDownloadFountain || p == LegProfileEchoBidi
}

// primesDownlinkPumpAtDial starts background body reader before first ReadFrom (bidi echo).
func (p LegProfile) primesDownlinkPumpAtDial() bool {
	return p == LegProfileEchoBidi
}

// serverDownlinkBulkImmediateFlush: fountain S2C — flush in bulk FSM without debounce timer.
func (p LegProfile) serverDownlinkBulkImmediateFlush() bool {
	return p == LegProfileDownloadFountain
}

func (p LegProfile) serverDownlinkImmediateFlush() bool {
	return false
}

func newH2DownlinkWriter(w http.ResponseWriter, profile LegProfile) *H2ResponseWriter {
	immediate := profile.serverDownlinkImmediateFlush()
	bulkImmediate := profile.serverDownlinkBulkImmediateFlush()
	return &H2ResponseWriter{
		ResponseWriter:       w,
		immediateFlush:       immediate,
		bulkImmediateFlush:   bulkImmediate,
	}
}
