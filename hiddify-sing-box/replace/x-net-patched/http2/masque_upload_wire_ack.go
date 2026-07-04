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

// MasqueSustainedUploadPumpAfterHeaders is the exported sustained-pump probe for masque tests.
func MasqueSustainedUploadPumpAfterHeaders(body io.ReadCloser) bool {
	return masqueSustainedUploadPumpAfterHeaders(body)
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


// masquePreserveConnectUploadPump marks upload bodies that must keep writeRequestBody
// active after response END_STREAM (CONNECT-UDP / CONNECT-IP asymmetric upload leg).
// CONNECT-stream must not match on wire-ack type alone — only an open upload writer arms duplex.
func masquePreserveConnectUploadPump(body io.ReadCloser) bool {
	return masqueUploadWriterOpen(body)
}

// masqueDeferConnectUploadBodyClose reports upload bodies that must not be torn down when the
// CONNECT response body arrives (CONNECT-stream sustained pump + asymmetric UDP/IP writer-live).
func masqueDeferConnectUploadBodyClose(body io.ReadCloser) bool {
	return masqueSustainedUploadPumpAfterHeaders(body)
}

// MasquePreserveConnectUploadBody is the exported preserve probe for package masque tests.
func MasquePreserveConnectUploadBody(body io.ReadCloser) bool {
	return masquePreserveConnectUploadPump(body)
}

// MasqueExtendedCONNECTUploadDuplex is the exported duplex probe for package masque tests.
func MasqueExtendedCONNECTUploadDuplex(isExtendedConnect bool, body io.ReadCloser, contentLen int64) bool {
	return masqueExtendedCONNECTUploadDuplex(isExtendedConnect, body, contentLen)
}

// masqueExtendedCONNECTUploadDuplex reports RFC 8441 Extended CONNECT upload streams that must
// keep pumping after response END_STREAM (connect-ip-go / CONNECT-UDP asymmetric upload leg).
func masqueExtendedCONNECTUploadDuplex(isExtendedConnect bool, body io.ReadCloser, contentLen int64) bool {
	_ = isExtendedConnect
	_ = contentLen
	return masqueSustainedUploadPumpAfterHeaders(body)
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
// nears capacity (bulk pipe cap is 512KiB; flush at 256KiB = TLS bulk threshold).
var masqueUploadPipeFlushWaterMark = 256 << 10

// SetMasqueUploadPipeFlushWaterMarkBytes overrides pipe watermark (bisect / unit tests only).
func SetMasqueUploadPipeFlushWaterMarkBytes(n int) {
	if n > 0 {
		masqueUploadPipeFlushWaterMark = n
	}
}

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

// masqueShouldBootstrapUploadFlush is an alias for the top-of-loop interactive flush gate.
func masqueShouldBootstrapUploadFlush(body io.ReadCloser, pendingAck int) bool {
	return masqueShouldInteractiveUploadFlush(body, pendingAck)
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
		// CONNECT-stream (no writer-live): flush pending DATA before blocking Read (H2 bidi FC).
		if !masqueUploadWriterOpen(body) {
			return true
		}
		return masqueShouldInteractiveUploadFlush(body, pendingAck)
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
