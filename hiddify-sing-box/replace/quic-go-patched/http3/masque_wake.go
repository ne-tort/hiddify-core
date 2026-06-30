package http3

import (
	"github.com/quic-go/quic-go"
)

func masqueWakeSendAfterReceiveRead(str *Stream, n int) {
	masqueWakeSendAfterBidiProgress(str, n)
}

func masqueWakeSendAfterDownloadWrite(str *Stream, n int) {
	masqueWakeSendAfterBidiProgress(str, n, quic.MasqueIsBidiDownloadActive)
}

func masqueWakeSendAfterUploadWrite(str *Stream, n int) {
	masqueWakeSendAfterUploadChunk(str, n)
}

// Prod wake: stream send only during saturated duplex (no S2C WINDOW poke on upload chunks).
func masqueWakeSendAfterUploadChunk(str *Stream, n int) {
	if n <= 0 || str == nil {
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
	if quic.MasqueIsBidiDuplexUploadStarted(qs) {
		quic.MasqueRepromoteDuplexUploadSend(qs)
		quic.MasqueWakeStreamSend(qs)
		return
	}
	if quic.MasqueIsBidiDownloadActive(qs) {
		quic.MasquePokeDownloadReceiveWindow(qs)
	}
	quic.MasqueWakeStreamSend(qs)
}

func masqueWakeSendAfterBidiProgress(str *Stream, n int, active ...func(*quic.Stream) bool) {
	if n <= 0 || str == nil {
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
	if quic.MasqueIsBidiDuplexUploadStarted(qs) {
		if quic.MasqueIsBidiDownloadActive(qs) &&
			quic.MasqueDuplexGrantPeerDownloadCredit(qs) {
			quic.MasquePokeDownloadReceiveWindow(qs)
		}
		quic.MasqueRepromoteDuplexUploadSend(qs)
		quic.MasqueWakeStreamSend(qs)
		return
	}
	if quic.MasqueConcurrentUploadPending(qs) && quic.MasqueIsBidiDownloadActive(qs) {
		quic.MasqueRepromoteDuplexUploadSend(qs)
		quic.MasqueWakeStreamSend(qs)
		return
	}
	if quic.MasqueIsBidiDownloadReceiveOnly(qs) && !quic.MasqueIsBidiDuplexUploadStarted(qs) {
		quic.MasquePokeDownloadReceiveWindow(qs)
		quic.MasquePokeConnPeerUploadCredit(qs)
		quic.MasqueWakeStreamSend(qs)
		return
	}
	if quic.MasqueIsBidiDownloadActive(qs) &&
		quic.MasqueDuplexGrantPeerDownloadCredit(qs) {
		quic.MasquePokeDownloadReceiveWindow(qs)
	}
	quic.MasqueWakeStreamSend(qs)
}
