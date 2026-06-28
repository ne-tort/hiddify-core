package conn

import (
	"os"
	"strconv"
	"strings"
)

const (
	EnvH2ConnectUploadChunk     = "MASQUE_H2_CONNECT_UPLOAD_CHUNK"
	EnvH2ConnectUploadBulkFlush = "MASQUE_H2_CONNECT_UPLOAD_BULK_FLUSH"
)

// defaultH2ConnectUploadChunkBytes matches bidiTunnelWriteToBufLen (64 KiB).
const defaultH2ConnectUploadChunkBytes = 64 * 1024

// H2UploadPolicy is the single load site for MASQUE_H2_CONNECT_UPLOAD_* env knobs.
// WrapChunkBytes controls H2 upload-body chunking (0 = passthrough when bulk flush owns the wire).
// ReadChunkBytes controls ReadFrom/bootstrap sizing (stays 64 KiB when wrap is passthrough).
type H2UploadPolicy struct {
	wrapChunkBytes int
	readChunkBytes int
	bulkFlush      bool
}

func (p H2UploadPolicy) WrapChunkBytes() int  { return p.wrapChunkBytes }
func (p H2UploadPolicy) ReadChunkBytes() int  { return p.readChunkBytes }
func (p H2UploadPolicy) BulkFlushEnabled() bool { return p.bulkFlush }

// CurrentH2UploadPolicy returns the active H2 CONNECT-stream upload policy.
func CurrentH2UploadPolicy() H2UploadPolicy {
	return loadH2UploadPolicy()
}

// H2ConnectUploadChunkBytes returns the ReadFrom/bootstrap upload chunk size.
func H2ConnectUploadChunkBytes() int {
	return CurrentH2UploadPolicy().ReadChunkBytes()
}

func loadH2UploadPolicy() H2UploadPolicy {
	bulk := h2ConnectUploadBulkFlushEnabled()
	wrap, read := h2UploadChunkBytesFromEnv(os.Getenv(EnvH2ConnectUploadChunk), bulk)
	return H2UploadPolicy{
		wrapChunkBytes: wrap,
		readChunkBytes: read,
		bulkFlush:      bulk,
	}
}

func h2ConnectUploadBulkFlushEnabled() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(EnvH2ConnectUploadBulkFlush))) {
	case "0", "false", "no", "off":
		return false
	default:
		return true
	}
}

func h2UploadChunkBytesFromEnv(raw string, bulkFlush bool) (wrapChunk, readChunk int) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		if bulkFlush {
			return 0, defaultH2ConnectUploadChunkBytes
		}
		return defaultH2ConnectUploadChunkBytes, defaultH2ConnectUploadChunkBytes
	}
	kb, err := strconv.Atoi(raw)
	if err != nil || kb <= 0 {
		if bulkFlush {
			return 0, defaultH2ConnectUploadChunkBytes
		}
		return defaultH2ConnectUploadChunkBytes, defaultH2ConnectUploadChunkBytes
	}
	if kb > 1024 {
		kb = 1024
	}
	chunk := kb * 1024
	return chunk, chunk
}
