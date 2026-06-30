package conn

// defaultH2ConnectUploadChunkBytes matches bidiTunnelWriteToBufLen (64 KiB).
const defaultH2ConnectUploadChunkBytes = 64 * 1024

// H2UploadPolicy is the prod H2 CONNECT-stream upload shape (bulk passthrough, 64 KiB read chunks).
type H2UploadPolicy struct {
	readChunkBytes int
}

func (p H2UploadPolicy) ReadChunkBytes() int { return p.readChunkBytes }

// CurrentH2UploadPolicy returns the active H2 CONNECT-stream upload policy.
func CurrentH2UploadPolicy() H2UploadPolicy {
	return H2UploadPolicy{readChunkBytes: defaultH2ConnectUploadChunkBytes}
}

// H2ConnectUploadChunkBytes returns the ReadFrom/bootstrap upload chunk size.
func H2ConnectUploadChunkBytes() int {
	return CurrentH2UploadPolicy().ReadChunkBytes()
}
