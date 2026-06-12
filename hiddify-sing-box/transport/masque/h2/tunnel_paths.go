package h2

import (
	"io"

	strm "github.com/sagernet/sing-box/transport/masque/stream"
)

// NewTunnelPaths builds H2 CONNECT upload/download halves with chunked upload policy applied.
func NewTunnelPaths(body io.ReadCloser, uploadPipe *io.PipeWriter) strm.TunnelPaths {
	policy := H2UploadFlushPolicy()
	return strm.TunnelPaths{
		Download: strm.NewH2DownloadPath(body),
		Upload:   strm.NewUploadPath(policy.Wrap(uploadPipe)),
	}
}
