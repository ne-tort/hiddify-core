package h3

import (
	"os"
	"strings"
)

// IngressAckWakeHTTPLayerH2 is the HTTP overlay tag where MasqueWakeSend must not run.
const IngressAckWakeHTTPLayerH2 = "h2"

// MasqueWakeSender is implemented by *http3.ClientConn for CONNECT-IP ingress ACK wake.
type MasqueWakeSender interface {
	MasqueWakeSend()
}

// IngressAckWakeOnReceiveRead reports whether quic-go may MasqueWakeStreamSend after CONNECT
// stream response Read. Set MASQUE_QUIC_WAKE_SEND_ON_RECEIVE_READ=0 to disable conn-wide wake
// during bidi bulk localize (CONNECT-stream upload on the same QUIC connection).
func IngressAckWakeOnReceiveRead() bool {
	return strings.TrimSpace(os.Getenv("MASQUE_QUIC_WAKE_SEND_ON_RECEIVE_READ")) != "0"
}

// FlushConnectIPIngressAckWake schedules QUIC egress after CONNECT-IP ingress TCP ACK/DATA.
// H2 overlay consumes the wake without MasqueWakeSend; H3 calls MasqueWakeConnSend only here.
func FlushConnectIPIngressAckWake(httpLayer string, conn MasqueWakeSender) {
	if httpLayer == IngressAckWakeHTTPLayerH2 || conn == nil {
		return
	}
	conn.MasqueWakeSend()
}
