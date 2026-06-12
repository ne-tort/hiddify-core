package relay

// Kernel and flush tuning exported for unit tests and ops introspection.
const (
	// TCPCopyBufLen is the io.CopyBuffer size for bulk CONNECT-stream relay.
	TCPCopyBufLen = 8 * 1024 * 1024

	// TCPDownloadFlushEvery batches HTTP response flushes on the legacy relay download leg.
	TCPDownloadFlushEvery = 32 * 1024

	// TCPDownloadReadLen is the TCP read size for legacy download copy.
	TCPDownloadReadLen = 512 * 1024

	// TCPUploadReadLen is the CONNECT request-body read size toward onward TCP.
	TCPUploadReadLen = 512 * 1024

	// TCPResponseFlushEvery batches HTTP/2–3 flushes to one per bulk relay read.
	TCPResponseFlushEvery = TCPCopyBufLen

	// TCPResponseFlushImmediate flushes first-flight and sub-4KiB tails promptly.
	TCPResponseFlushImmediate = 4096

	// TCPKernelBuf is a best-effort SO_RCVBUF/SO_SNDBUF for onward TCP dials.
	TCPKernelBuf = 16 << 20
)
