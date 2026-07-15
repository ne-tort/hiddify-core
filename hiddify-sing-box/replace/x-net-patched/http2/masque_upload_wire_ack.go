package http2

import (
	"io"
	"net/http"
)

// masqueUploadWriterOpenState reports whether the client upload pipe writer is still open
// (defer HTTP/2 END_STREAM until half-close — connect-ip-go / Invisv bidi parity).
type masqueUploadWriterOpenState interface {
	MasqueUploadWriterOpen() bool
}

func masqueUploadWriterOpen(body io.ReadCloser) bool {
	if body == nil {
		return false
	}
	if w, ok := body.(masqueUploadWriterOpenState); ok {
		return w.MasqueUploadWriterOpen()
	}
	return false
}

// masqueConnectStreamBidiUploadBody marks RFC 8441 CONNECT-stream upload bodies that need a
// sustained upload pump (defer END_STREAM) without asymmetric UDP/IP writer-live semantics.
type masqueConnectStreamBidiUploadBody interface {
	MasqueConnectStreamBidiUpload() bool
}

func masqueConnectStreamBidiUpload(body io.ReadCloser) bool {
	if body == nil {
		return false
	}
	b, ok := body.(masqueConnectStreamBidiUploadBody)
	return ok && b.MasqueConnectStreamBidiUpload()
}

// masqueUploadPipeWriterOpenState reports whether the app upload pipe writer is still open.
type masqueUploadPipeWriterOpenState interface {
	MasqueUploadPipeWriterOpen() bool
}

func masqueUploadPipeWriterOpen(body io.ReadCloser) bool {
	if body == nil {
		return false
	}
	if masqueUploadWriterOpen(body) {
		return true
	}
	w, ok := body.(masqueUploadPipeWriterOpenState)
	return ok && w.MasqueUploadPipeWriterOpen()
}

// masqueSustainedUploadPumpAfterHeaders reports bodies that must not half-close upload after
// the first writeRequestBody drain (CONNECT-stream bidi or asymmetric UDP/IP writer-live).
func masqueSustainedUploadPumpAfterHeaders(body io.ReadCloser) bool {
	return masqueUploadWriterOpen(body) || masqueConnectStreamBidiUpload(body)
}

// masqueSustainedUploadPumpContinue reports whether the sustained upload pump should keep looping.
func masqueSustainedUploadPumpContinue(body io.ReadCloser) bool {
	if masqueUploadWriterOpen(body) {
		return true
	}
	if !masqueConnectStreamBidiUpload(body) {
		return false
	}
	return masqueUploadPumpActive(body)
}

// masqueUploadPumpActive reports whether writeRequestBody must keep draining the upload leg.
func masqueUploadPumpActive(body io.ReadCloser) bool {
	if b, ok := body.(masqueUploadBuffered); ok && b.MasqueUploadBuffered() > 0 {
		return true
	}
	return masqueUploadPipeWriterOpen(body)
}

// masqueUploadWireAck is implemented by MASQUE H2 Extended CONNECT upload bodies.
type masqueUploadWireAck interface {
	MasqueUploadWireAck(n int)
}

// reqIsMasqueExtendedCONNECT reports RFC 8441 Extended CONNECT (capture at RoundTrip — :protocol may leave req.Header before writeRequest).
func reqIsMasqueExtendedCONNECT(req *http.Request) bool {
	if req == nil || req.Method != "CONNECT" {
		return false
	}
	if req.Header.Get(":protocol") != "" {
		return true
	}
	return req.Header.Get("Capsule-Protocol") != "" || req.Header.Get("capsule-protocol") != ""
}

// masqueUploadBuffered reports upload pipe depth for flush-before-blocking-read policy.
type masqueUploadBuffered interface {
	masqueUploadWireAck
	MasqueUploadBuffered() int
}

// masqueUploadBootstrap reports Invisv io.Pipe upload bootstrap vs bulk TLS batching.
type masqueUploadBootstrap interface {
	UploadBootstrapPending() bool
	UploadBulkArmed() bool
}

// masqueUploadPipeCap reports shallow upload pipe capacity (CONNECT-UDP 64KiB).
type masqueUploadPipeCap interface {
	UploadPipeCap() int
}

// masqueUploadPipeFlushWaterMark: flush sub-threshold TLS DATA when upload pipe depth
// nears capacity (CONNECT-stream pipe = 256 KiB = TLS bulk threshold).
var masqueUploadPipeFlushWaterMark = 256 << 10

func masqueUploadPipeFlushMark(body io.ReadCloser) int {
	mark := masqueUploadPipeFlushWaterMark
	if cap, ok := body.(masqueUploadPipeCap); ok {
		if c := cap.UploadPipeCap(); c > 0 && c < mark {
			mark = c / 2
			if mark < 8<<10 {
				mark = 8 << 10
			}
		}
	}
	return mark
}

// masqueShouldInteractiveUploadFlush flushes before blocking Read during bootstrap only.
// After UploadBulkArmed, sustained upload defers to masqueShouldBulkFlushNow/Deadline.
func masqueShouldInteractiveUploadFlush(body io.ReadCloser, pendingAck int) bool {
	if pendingAck <= 0 {
		return false
	}
	bp, ok := body.(masqueUploadBootstrap)
	if !ok || bp.UploadBulkArmed() {
		return false
	}
	return bp.UploadBootstrapPending()
}

// masqueShouldFlushBeforeBlockingRead flushes sub-threshold DATA before a blocking body.Read.
func masqueShouldFlushBeforeBlockingRead(body io.ReadCloser, pendingAck int) bool {
	if pendingAck <= 0 {
		return false
	}
	b, ok := body.(masqueUploadBuffered)
	if !ok {
		return false
	}
	switch buf := b.MasqueUploadBuffered(); {
	case buf < 0:
		return false
	case buf == 0:
		if masqueUploadWriterOpen(body) {
			// CONNECT-UDP/IP writer-live: interactive flush only during bootstrap.
			return masqueShouldInteractiveUploadFlush(body, pendingAck)
		}
		// CONNECT-stream: MUST Flush any pending before blocking Read — deadline is not
		// polled while blocked, so returning false with pendingAck>0 stalls the wire
		// (field: armed MinPending=256 → up ~7 Mbit). Coalesce lives in bulk Now/deadline
		// while pipe stays non-empty; empty-pipe quantum = pipe cap (256 KiB).
		return true
	default:
		return buf >= masqueUploadPipeFlushMark(body)
	}
}

func masqueAckUploadWireSent(body io.ReadCloser, n int) {
	if body == nil || n <= 0 {
		return
	}
	if a, ok := body.(masqueUploadWireAck); ok {
		a.MasqueUploadWireAck(n)
	}
}
