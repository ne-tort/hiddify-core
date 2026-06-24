package h2

import (
	"os"
	"strconv"
	"strings"
)

const envH2ConnectUDPUploadStreams = "MASQUE_H2_CONNECT_UDP_UPLOAD_STREAMS"

// UploadStreamsConfigured returns parallel upload-only CONNECT-UDP legs when asymmetric duplex is on (default 1).
func UploadStreamsConfigured() int {
	v := strings.TrimSpace(os.Getenv(envH2ConnectUDPUploadStreams))
	if v == "" {
		return 1
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 1 {
		return 1
	}
	if n > 8 {
		return 8
	}
	return n
}
