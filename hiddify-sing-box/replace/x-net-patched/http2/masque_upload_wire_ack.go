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

// masqueUploadPumpActive reports whether writeRequestBody must keep draining the upload
// leg (Invisv io.Pipe: writer open or buffered bytes remain in the shallow pipe).
func masqueUploadPumpActive(body io.ReadCloser) bool {
	if masqueUploadWriterOpen(body) {
		return true
	}
	if b, ok := body.(masqueUploadBuffered); ok {
		return b.MasqueUploadBuffered() > 0
	}
	return false
}

// masqueUploadWireAck is implemented by MASQUE H2 Extended CONNECT upload bodies.
type masqueUploadWireAck interface {
	MasqueUploadWireAck(n int)
}


// masquePreserveConnectUploadPump marks upload bodies that must keep writeRequestBody
// active after response END_STREAM (CONNECT-UDP / CONNECT-IP asymmetric upload leg).
func masquePreserveConnectUploadPump(body io.ReadCloser) bool {
	if body == nil {
		return false
	}
	if _, ok := body.(masqueUploadWireAck); ok {
		return true
	}
	// ExtendedConnectUploadBody / connect-ip-go duplex bodies (writer-open discriminator).
	_, ok := body.(masqueUploadWriterOpenState)
	return ok
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
	// Duplex body shape wins over :protocol capture timing (Invisv / connect-ip-go).
	if masquePreserveConnectUploadPump(body) {
		return true
	}
	if !isExtendedConnect {
		return false
	}
	return body != nil && contentLen != 0
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
const masqueUploadPipeFlushWaterMark = 256 << 10

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
