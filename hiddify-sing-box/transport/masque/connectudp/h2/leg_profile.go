package h2

// LegProfile tags asymmetric stream role.
// Upload: immediate C2S flush per WriteTo when not duplex-active (64KiB coalesce
// threshold exists but is unreachable on this profile — AUDIT B6 / TASKS F1.3).
// DownloadFountain: S2C bulk threshold flush. Bidi: immediate C2S.
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
