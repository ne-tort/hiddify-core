package http2

func init() {
	// MASQUE requires RFC 8441 Extended CONNECT (upstream defaults off).
	disableExtendedConnectProtocol = false
}
