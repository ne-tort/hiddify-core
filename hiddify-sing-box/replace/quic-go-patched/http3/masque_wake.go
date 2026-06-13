package http3

import (
	"os"
	"strings"

	"github.com/quic-go/quic-go"
)

const envBidiConnWake = "MASQUE_QUIC_BIDI_CONN_WAKE"

// masqueWakeSendOnReceiveRead is on unless MASQUE_QUIC_WAKE_SEND_ON_RECEIVE_READ=0.
func masqueWakeSendOnReceiveRead() bool {
	return strings.TrimSpace(os.Getenv("MASQUE_QUIC_WAKE_SEND_ON_RECEIVE_READ")) != "0"
}

// masqueWakeBidiConnOnReceiveRead enables conn-level send scheduling after bidi download reads.
// Default on; disable with MASQUE_QUIC_BIDI_CONN_WAKE=0 (Q7 wave 2).
func masqueWakeBidiConnOnReceiveRead() bool {
	return strings.TrimSpace(os.Getenv(envBidiConnWake)) != "0"
}

// masqueWakeSendAfterReceiveRead wakes QUIC send after HTTP/3 Stream.Read delivered payload.
// Call site is Stream.Read only (not body/stateTrackingStream) to avoid double MasqueWakeStreamSend.
func masqueWakeSendAfterReceiveRead(str *Stream, n int) {
	masqueWakeSendAfterBidiProgress(str, n)
}

// masqueWakeSendAfterDownloadWrite schedules send after HTTP/3 Stream.Write queues download
// payload on a download-active bidi leg (server hijack relay). Same env gates as receive wake.
func masqueWakeSendAfterDownloadWrite(str *Stream, n int) {
	masqueWakeSendAfterBidiProgress(str, n, quic.MasqueIsBidiDownloadActive)
}

func masqueWakeSendAfterBidiProgress(str *Stream, n int, active ...func(*quic.Stream) bool) {
	if n <= 0 || !masqueWakeSendOnReceiveRead() || str == nil {
		return
	}
	ds := str.datagramStream
	if ds == nil {
		return
	}
	qs := ds.QUICStream()
	if qs == nil {
		return
	}
	if len(active) > 0 && active[0] != nil && !active[0](qs) {
		return
	}
	if quic.MasqueDownloadEagerWindowEnabled() {
		quic.MasquePokeDownloadReceiveWindow(qs)
	}
	if masqueWakeBidiConnOnReceiveRead() {
		quic.MasqueWakeBidiDuplex(qs)
		return
	}
	quic.MasqueWakeStreamSend(qs)
}
