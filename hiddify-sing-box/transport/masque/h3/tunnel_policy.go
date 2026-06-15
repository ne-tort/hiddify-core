package h3

import strm "github.com/sagernet/sing-box/transport/masque/stream"

// ConnectStreamMode names the client-side H3 CONNECT-stream dataplane.
type ConnectStreamMode string

const (
	ConnectStreamModeSingleBidi ConnectStreamMode = "single_bidi"
)

// CurrentConnectStreamMode reports the effective H3 CONNECT-stream mode.
func CurrentConnectStreamMode() ConnectStreamMode {
	return ConnectStreamModeSingleBidi
}

// ConnectStreamRole is the role of one H3 CONNECT stream in the selected dataplane.
type ConnectStreamRole string

const (
	ConnectStreamRoleSingle   ConnectStreamRole = ""
	ConnectStreamRoleDownload ConnectStreamRole = strm.ConnectStreamLegDownload
	ConnectStreamRoleUpload   ConnectStreamRole = strm.ConnectStreamLegUpload
)

func normalizeConnectStreamRole(role string) ConnectStreamRole {
	switch role {
	case strm.ConnectStreamLegDownload:
		return ConnectStreamRoleDownload
	case strm.ConnectStreamLegUpload:
		return ConnectStreamRoleUpload
	default:
		return ConnectStreamRoleSingle
	}
}

func (r ConnectStreamRole) String() string { return string(r) }

func (r ConnectStreamRole) IsSingleBidi() bool { return r == ConnectStreamRoleSingle }

func (r ConnectStreamRole) IsDownloadLeg() bool { return r == ConnectStreamRoleDownload }

func (r ConnectStreamRole) IsUploadLeg() bool { return r == ConnectStreamRoleUpload }
