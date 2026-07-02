package conn

import cudpasym "github.com/sagernet/sing-box/transport/masque/connectudp/asym"

// H3LegRole tags asymmetric CONNECT-UDP legs on the client (metadata only).
type H3LegRole uint8

const (
	H3LegBidi H3LegRole = iota
	H3LegDownload
	H3LegUpload
)

// H3ConnConfig tags asymmetric CONNECT-UDP legs on the client.
type H3ConnConfig struct {
	LegRole H3LegRole
}

// H3LegRoleFromStreamRole maps Masque-Udp-Stream-Role to client leg profile.
func H3LegRoleFromStreamRole(streamRole string) H3LegRole {
	switch streamRole {
	case cudpasym.StreamRoleDownload:
		return H3LegDownload
	case cudpasym.StreamRoleUpload:
		return H3LegUpload
	default:
		return H3LegBidi
	}
}
