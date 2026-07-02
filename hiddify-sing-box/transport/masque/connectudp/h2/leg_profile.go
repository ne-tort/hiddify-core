package h2

// LegProfile tags asymmetric stream role.
// Upload: bulk threshold coalesce (64–128 KiB). DownloadFountain: S2C bulk threshold flush. Bidi: immediate C2S.
type LegProfile uint8

const (
	LegProfileUpload LegProfile = iota
	LegProfileDownloadFountain
	LegProfileBidi
)

func legProfileForStreamRole(role streamRole) LegProfile {
	switch role {
	case streamRoleUpload:
		return LegProfileUpload
	case streamRoleDownload:
		return LegProfileDownloadFountain
	default:
		return LegProfileBidi
	}
}

func (p LegProfile) uploadImmediateFlush() bool {
	return p == LegProfileUpload
}

// uploadNoCoalesceTimer: upload leg uses sync threshold flush only (no debounce timer).
func (p LegProfile) uploadNoCoalesceTimer() bool {
	return p == LegProfileUpload
}
