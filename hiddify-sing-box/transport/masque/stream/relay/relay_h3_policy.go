package relay

// RelayH3ConnectMode selects the server-side H3 CONNECT-stream relay shape.
// Wire: each mode is still a standard RFC 9114 CONNECT; only relay goroutine layout differs.
type RelayH3ConnectMode int

const (
	// RelayH3ConnectModeBidi runs upload+download on one hijacked HTTP/3 stream (prod default).
	RelayH3ConnectModeBidi RelayH3ConnectMode = iota
	// RelayH3ConnectModeDownloadLeg relays onward TCP → HTTP/3 only (P2/P6 download CONNECT).
	RelayH3ConnectModeDownloadLeg
	// RelayH3ConnectModeUploadLeg relays HTTP/3 → onward TCP only (P2/P6 upload CONNECT).
	RelayH3ConnectModeUploadLeg
)

const (
	connectStreamLegDownload = "download"
	connectStreamLegUpload   = "upload"
)

// RelayH3ConnectModeFromLegRole maps Masque-Connect-Stream-Leg to relay mode.
// Values match stream.ConnectStreamLegDownload / ConnectStreamLegUpload.
// Empty legRole means single bidi CONNECT.
func RelayH3ConnectModeFromLegRole(legRole string) RelayH3ConnectMode {
	switch legRole {
	case connectStreamLegDownload:
		return RelayH3ConnectModeDownloadLeg
	case connectStreamLegUpload:
		return RelayH3ConnectModeUploadLeg
	default:
		return RelayH3ConnectModeBidi
	}
}
