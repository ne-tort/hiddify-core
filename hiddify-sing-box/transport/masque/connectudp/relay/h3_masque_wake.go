package relay

import (
	"github.com/quic-go/quic-go/http3"
)

// wakeH3RelayAfterC2SConsume grants sibling upload QUIC FC after HTTP/3 DATAGRAM drain
// (quic-go-patched http3.WakeMasqueRelayAfterUploadRead; asymmetric upload + bidi C2S relay).
func wakeH3RelayAfterC2SConsume(str h3C2SStream) {
	if str == nil {
		return
	}
	if s, ok := str.(*http3.Stream); ok {
		http3.WakeMasqueRelayAfterUploadRead(s)
	}
}

// wakeH3RelayAfterS2CSendPressure nudges QUIC datagram send after transient S2C pressure (zero-loss retry path).
func wakeH3RelayAfterS2CSendPressure(str h3DatagramSender) {
	if str == nil {
		return
	}
	if f, ok := str.(interface{ FlushProxiedIPDatagramSend() }); ok {
		f.FlushProxiedIPDatagramSend()
	}
	if s, ok := str.(*http3.Stream); ok {
		http3.WakeMasqueRelayAfterUploadRead(s)
	}
}
