package h2

// UploadStreamsConfigured returns parallel upload-only CONNECT-UDP legs when asymmetric duplex is on (default 1).
func UploadStreamsConfigured() int {
	return parseUploadStreamsEnv()
}
