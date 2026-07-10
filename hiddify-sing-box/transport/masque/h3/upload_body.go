package h3

// H3UploadFlushChunkBytes splits bulk CONNECT-stream upload before hitting the wire (64 KiB).
const H3UploadFlushChunkBytes = connectStreamBufLen

// H3UploadChunkBytes returns CONNECT upload chunk size.
func H3UploadChunkBytes(downloadActive bool, downloadDelivered bool, duplexUploadStarted bool) int {
	_ = downloadActive
	_ = downloadDelivered
	_ = duplexUploadStarted
	return connectStreamBufLen
}
