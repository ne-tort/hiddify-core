package http2

import (
	"io"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	envH2UploadBulkFlush         = "MASQUE_H2_CONNECT_UPLOAD_BULK_FLUSH"
	envH2UploadBulkFlushBytes    = "MASQUE_H2_UPLOAD_BULK_FLUSH_BYTES"
	envH2UploadBulkFlushMaxMs    = "MASQUE_H2_UPLOAD_BULK_FLUSH_MAX_MS"
	envH2UploadBulkFlushMinBytes = "MASQUE_H2_UPLOAD_BULK_FLUSH_MIN_BYTES"
)

func masqueUploadBulkFlushEnabled() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(envH2UploadBulkFlush))) {
	case "0", "false", "no", "off":
		return false
	default:
		return true
	}
}

// masqueBulkFlushThreshold returns bytes to batch before TLS flush in bulk mode.
// Default 64 KiB: instant burst ~485 Mbit/s; deadline flush prevents upload-pipe stall.
func masqueBulkFlushThreshold() int {
	if v := strings.TrimSpace(os.Getenv(envH2UploadBulkFlushBytes)); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			return n
		}
	}
	return 64 << 10
}

func masqueBulkFlushMinPending() int {
	if v := strings.TrimSpace(os.Getenv(envH2UploadBulkFlushMinBytes)); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
	}
	return 32 << 10
}

func masqueBulkFlushMaxDelay() time.Duration {
	if v := strings.TrimSpace(os.Getenv(envH2UploadBulkFlushMaxMs)); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			return time.Duration(n) * time.Millisecond
		}
	}
	return 2 * time.Millisecond
}

func masqueShouldBulkFlushNow(pendingAck int, sawEOF bool) bool {
	if pendingAck <= 0 {
		return false
	}
	if sawEOF || !masqueUploadBulkFlushEnabled() {
		return true
	}
	th := masqueBulkFlushThreshold()
	if th <= 0 {
		return true
	}
	return pendingAck >= th
}

// masqueShouldBulkFlushDeadline flushes sustained upload below byte threshold (pipe backpressure / duplex wake).
func masqueShouldBulkFlushDeadline(pendingAck int, firstPendingAt time.Time) bool {
	if pendingAck <= 0 || firstPendingAt.IsZero() {
		return false
	}
	return time.Since(firstPendingAt) >= masqueBulkFlushMaxDelay()
}

func masqueUploadBodyUsesBulkFlush(body io.ReadCloser) bool {
	if body == nil || !masqueUploadBulkFlushEnabled() {
		return false
	}
	_, ok := body.(masqueUploadWireAck)
	return ok
}
