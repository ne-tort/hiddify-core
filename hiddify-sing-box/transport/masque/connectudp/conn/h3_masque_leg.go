package conn

import (
	"github.com/quic-go/quic-go"
)

type h3QUICStream interface {
	QUICStream() *quic.Stream
}

// armH3AsymmetricDownloadLeg marks P2 download receive-active on the QUIC stream (H3-L1c-7).
// Sibling upload on the same conn needs conn MAX_DATA poke without framer send boost.
func armH3AsymmetricDownloadLeg(str http3Stream) {
	qs, ok := str.(h3QUICStream)
	if !ok || qs.QUICStream() == nil {
		return
	}
	s := qs.QUICStream()
	quic.MasqueSetPeerDuplexLazyFC(s, true)
	quic.MasqueSetBidiDownloadReceiveActive(s, true)
}

func disarmH3AsymmetricDownloadLeg(str http3Stream) {
	qs, ok := str.(h3QUICStream)
	if !ok || qs.QUICStream() == nil {
		return
	}
	s := qs.QUICStream()
	quic.MasqueSetBidiDownloadReceiveActive(s, false)
	quic.MasqueSetPeerDuplexLazyFC(s, false)
}
