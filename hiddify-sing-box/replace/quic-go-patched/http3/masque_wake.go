package http3

import (
	"os"
	"strings"

	"github.com/quic-go/quic-go"
)

// masqueWakeSendOnReceiveRead is on unless MASQUE_QUIC_WAKE_SEND_ON_RECEIVE_READ=0.
func masqueWakeSendOnReceiveRead() bool {
	return strings.TrimSpace(os.Getenv("MASQUE_QUIC_WAKE_SEND_ON_RECEIVE_READ")) != "0"
}

func masqueWakeSendAfterReceiveRead(str *Stream, n int) {
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
	quic.MasqueWakeStreamSend(qs)
}
