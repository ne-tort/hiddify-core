package h3

// IngressAckWakeHTTPLayerH2 is the HTTP overlay tag where MasqueWakeSend must not run.
const IngressAckWakeHTTPLayerH2 = "h2"

// MasqueWakeSender is implemented by *http3.ClientConn for CONNECT-IP ingress ACK wake.
type MasqueWakeSender interface {
	MasqueWakeSend()
}

// IngressAckWakeOnReceiveRead reports whether quic-go may MasqueWakeStreamSend after CONNECT
// stream response Read (prod: always on).
func IngressAckWakeOnReceiveRead() bool {
	return true
}
// FlushConnectIPIngressAckWake schedules QUIC egress after CONNECT-IP ingress TCP ACK/DATA.
// H2 overlay consumes the wake without MasqueWakeSend; H3 calls MasqueWakeConnSend only here.
func FlushConnectIPIngressAckWake(httpLayer string, conn MasqueWakeSender) {
	if httpLayer == IngressAckWakeHTTPLayerH2 || conn == nil {
		return
	}
	conn.MasqueWakeSend()
}
