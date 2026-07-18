package conn

// H3LegRole tags CONNECT-UDP client legs (metadata only; prod is always bidi).
type H3LegRole uint8

const (
	H3LegBidi H3LegRole = iota
	H3LegDownload
	H3LegUpload
)

// H3ConnConfig tags CONNECT-UDP client legs.
type H3ConnConfig struct {
	LegRole H3LegRole
}

// H3LegRoleFromStreamRole maps a legacy stream-role string to client leg profile.
func H3LegRoleFromStreamRole(streamRole string) H3LegRole {
	switch streamRole {
	case "download":
		return H3LegDownload
	case "upload":
		return H3LegUpload
	default:
		return H3LegBidi
	}
}
