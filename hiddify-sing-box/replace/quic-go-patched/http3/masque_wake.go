package http3

import (
	"os"
	"strings"

	"github.com/quic-go/quic-go"
)

const envBidiConnWake = "MASQUE_QUIC_BIDI_CONN_WAKE"

var masqueHTTP3WakeSendOnReceiveReadEnabled = true

func init() {
	if strings.TrimSpace(os.Getenv("MASQUE_QUIC_WAKE_SEND_ON_RECEIVE_READ")) == "0" {
		masqueHTTP3WakeSendOnReceiveReadEnabled = false
	}
}

func masqueWakeSendOnReceiveRead() bool {
	return masqueHTTP3WakeSendOnReceiveReadEnabled
}

func masqueWakeSendAfterReceiveRead(str *Stream, n int) {
	masqueWakeSendAfterBidiProgress(str, n)
}

func masqueWakeSendAfterDownloadWrite(str *Stream, n int) {
	masqueWakeSendAfterBidiProgress(str, n, quic.MasqueIsBidiDownloadActive)
}

func masqueWakeSendAfterUploadWrite(str *Stream, n int) {
	masqueWakeSendAfterUploadChunk(str, n)
}

// Prod wake: stream send only; skip WINDOW poke during saturated duplex (upload STREAM budget).
func masqueWakeSendAfterUploadChunk(str *Stream, n int) {
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
	if quic.MasqueIsBidiDownloadActive(qs) && !quic.MasqueIsBidiDuplexUploadStarted(qs) && quic.MasqueDownloadEagerWindowEnabled() {
		quic.MasquePokeDownloadReceiveWindow(qs)
	}
	quic.MasqueWakeStreamSend(qs)
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
	if !quic.MasqueIsBidiDuplexUploadStarted(qs) && quic.MasqueDownloadEagerWindowEnabled() {
		quic.MasquePokeDownloadReceiveWindow(qs)
	}
	quic.MasqueWakeStreamSend(qs)
}
