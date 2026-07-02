package h2

// LegProfile tags asymmetric stream role.
// Upload: thin immediate C2S. DownloadFountain: S2C bulk threshold flush. Bidi: h2o 1:1 immediate S2C.
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
