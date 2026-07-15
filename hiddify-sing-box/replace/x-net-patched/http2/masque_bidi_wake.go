package http2

import "io"

// masqueRequestBodyWake is implemented by MASQUE H2 Extended CONNECT upload bodies that can
// nudge writeRequestBody out of awaitFlowControl without a no-op pipe flush.
type masqueRequestBodyWake interface {
	MasqueWakeRequestBodyWrite()
}

// masqueWakeRequestBodyWrite schedules upload DATA on the CONNECT stream when supported.
func masqueWakeRequestBodyWrite(body io.ReadCloser) {
	if body == nil {
		return
	}
	if w, ok := body.(masqueRequestBodyWake); ok {
		w.MasqueWakeRequestBodyWrite()
	}
}

// masqueUploadNeedsDownloadWake reports whether a download Body.Read should poke the upload
// pump. Skip when upload is idle (CF long GET): per-Read wake fought wmu with WINDOW_UPDATE
// Flush and produced peak→plateau stock-window decay. Keep poke for buffered/bootstrap upload
// and asymmetric writer-live legs (iperf -R / CONNECT-UDP).
func masqueUploadNeedsDownloadWake(body io.ReadCloser) bool {
	if body == nil {
		return false
	}
	if b, ok := body.(masqueUploadBuffered); ok && b.MasqueUploadBuffered() > 0 {
		return true
	}
	if bp, ok := body.(masqueUploadBootstrap); ok && bp.UploadBootstrapPending() {
		return true
	}
	return masqueUploadWriterOpen(body)
}
