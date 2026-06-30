package conn

// defaultH2ConnectUploadChunkBytes matches bidiTunnelWriteToBufLen (64 KiB).
const defaultH2ConnectUploadChunkBytes = 64 * 1024

// H2ConnectUploadChunkBytes returns the ReadFrom/bootstrap upload chunk size.
func H2ConnectUploadChunkBytes() int {
	return defaultH2ConnectUploadChunkBytes
}
