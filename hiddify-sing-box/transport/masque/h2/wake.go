package h2

import "io"

// FlushConnectIPIngressAckWake pokes the H2 Extended CONNECT upload half after ingress TCP ACK/DATA.
func FlushConnectIPIngressAckWake(upload io.Writer) {
	FlushRequestBody(upload)
}
