package h3

import "github.com/quic-go/quic-go"

func primeH3ConnectStream(str h3ConnectStream) {
	if str == nil {
		return
	}
	qs := str.QUICStream()
	if qs == nil {
		return
	}
	quic.MasqueSetBidiDownloadReceiveActive(qs, true)
	quic.MasqueSetPeerDuplexLazyFC(qs, false)
	quic.MasqueBoostDuplexReceiveFC(qs)
	quic.MasquePokeDownloadReceiveWindow(qs)
	quic.MasquePokeConnPeerUploadCredit(qs)
	quic.MasqueWakeStreamSend(qs)
}
