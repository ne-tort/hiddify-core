package conn

// defaultH2ConnectUploadChunkBytes matches bidiTunnelWriteToBufLen (64 KiB).
const defaultH2ConnectUploadChunkBytes = 64 * 1024

// H2UploadPolicy is the prod H2 CONNECT-stream upload shape (bulk flush on, 64 KiB read chunks).
type H2UploadPolicy struct {
	wrapChunkBytes int
	readChunkBytes int
	bulkFlush      bool
}

func (p H2UploadPolicy) WrapChunkBytes() int    { return p.wrapChunkBytes }
func (p H2UploadPolicy) ReadChunkBytes() int    { return p.readChunkBytes }
func (p H2UploadPolicy) BulkFlushEnabled() bool { return p.bulkFlush }

// CurrentH2UploadPolicy returns the active H2 CONNECT-stream upload policy.
func CurrentH2UploadPolicy() H2UploadPolicy {
	return H2UploadPolicy{
		wrapChunkBytes: 0,
		readChunkBytes: defaultH2ConnectUploadChunkBytes,
		bulkFlush:      true,
	}
}

// H2ConnectUploadChunkBytes returns the ReadFrom/bootstrap upload chunk size.
func H2ConnectUploadChunkBytes() int {
	return CurrentH2UploadPolicy().ReadChunkBytes()
}
