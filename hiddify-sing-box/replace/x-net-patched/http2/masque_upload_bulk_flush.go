package http2

import (
	"io"
	"time"
)

func masqueUploadBulkFlushEnabled() bool { return true }

var masqueBulkFlushThresholdBytes = 256 << 10

// masqueBulkFlushThreshold returns bytes to batch before TLS flush in bulk mode.
func masqueBulkFlushThreshold() int { return masqueBulkFlushThresholdBytes }

// SetMasqueBulkFlushThresholdBytes overrides bulk TLS batch size (bisect / unit tests only).
func SetMasqueBulkFlushThresholdBytes(n int) {
	if n > 0 {
		masqueBulkFlushThresholdBytes = n
	}
}

func masqueBulkFlushMinPending() int { return 32 << 10 }

// masqueBulkFlushMaxDelay bounds time below byte threshold before TLS flush (io.Pipe upload).
// 3ms plateau ~620 Mbit/s maxCapsule on Windows synth (io.Pipe handoff identity); 2ms/4ms no delta.
func masqueBulkFlushMaxDelay() time.Duration { return 3 * time.Millisecond }

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
	if _, ok := body.(masqueUploadWireAck); !ok {
		return false
	}
	// CONNECT-UDP shallow pipe ≤64KiB: per-capsule TLS flush (h2o parity). >64KiB enables bulk batching.
	if cap, ok := body.(masqueUploadPipeCap); ok {
		if c := cap.UploadPipeCap(); c > 0 && c <= 64<<10 {
			return false
		}
	}
	return true
}
