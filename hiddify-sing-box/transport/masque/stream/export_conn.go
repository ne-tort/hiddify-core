package stream

import (
	"github.com/sagernet/sing-box/transport/masque/stream/conn"
)

// CONNECT-stream tunnel path types (M-S2) — implemented in stream/conn/.
type (
	DownloadPath      = conn.DownloadPath
	UploadPath        = conn.UploadPath
	TunnelPaths       = conn.TunnelPaths
	UploadWireBarrier = conn.UploadWireBarrier
)

var (
	NewTunnelPaths                 = conn.NewTunnelPaths
	NewH2DownloadPath              = conn.NewH2DownloadPath
	NewUploadPath                  = conn.NewUploadPath
	NewDownloadPathAdapter         = conn.NewDownloadPathAdapter
	ConnFromTunnelPaths            = conn.ConnFromTunnelPaths
	NewH2ConnectStreamResponseBody = conn.NewH2ConnectStreamResponseBody
	PrimeH2UploadBootstrapOnConn   = conn.PrimeH2UploadBootstrapOnConn
	H2BidiBootstrapUploadBytes     = conn.H2BidiBootstrapUploadBytes
	H2ConnectUploadChunkBytes      = conn.H2ConnectUploadChunkBytes
	ErrDeadlineUnsupported         = conn.ErrDeadlineUnsupported
)
