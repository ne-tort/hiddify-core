package h2

import "io"

// UploadFlushPolicy controls how bulk CONNECT-stream upload is split before hitting the wire.
// Prod uses bulk passthrough (ChunkBytes=0); H3 path keeps chunking in h3/upload_body.go.
type UploadFlushPolicy struct {
	ChunkBytes int
}

// H2UploadFlushPolicy returns the active H2 CONNECT-stream upload flush policy.
func H2UploadFlushPolicy() UploadFlushPolicy {
	return UploadFlushPolicy{ChunkBytes: 0}
}

// Wrap returns w unchanged (prod bulk passthrough; STR-4a4 removed chunkedUploadWriter).
func (p UploadFlushPolicy) Wrap(w io.WriteCloser) io.WriteCloser {
	return w
}
