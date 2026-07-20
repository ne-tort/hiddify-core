package h2

import "io"

// FlushConnectIPIngressAckWake pokes the H2 Extended CONNECT upload half after ingress TCP ACK/DATA.
// Shallow upload pipes implement PokeH2BidiDownload (masque/h2 parity); legacy io.Pipe falls back to FlushRequestBody.
func FlushConnectIPIngressAckWake(upload io.Writer) {
	if upload == nil {
		return
	}
	if p, ok := upload.(interface{ PokeH2BidiDownload() }); ok {
		p.PokeH2BidiDownload()
		return
	}
	FlushRequestBody(upload)
}
