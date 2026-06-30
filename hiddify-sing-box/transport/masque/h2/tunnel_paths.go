package h2

import (
	"io"

	strm "github.com/sagernet/sing-box/transport/masque/stream"
)

// NewTunnelPaths builds H2 CONNECT upload/download halves (bulk upload passthrough).
func NewTunnelPaths(body io.ReadCloser, uploadPipe io.WriteCloser) strm.TunnelPaths {
	return strm.TunnelPaths{
		Download: strm.NewH2DownloadPath(body),
		Upload:   strm.NewUploadPath(uploadPipe),
	}
}
