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
