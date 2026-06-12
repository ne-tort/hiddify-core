package session

// TCPHTTPTransportHost wires H2 CONNECT-stream pool reset for ResetTCPHTTPTransport.
type TCPHTTPTransportHost interface {
	ResetH2ConnectStreamTransportLockedAssumeMu()
}
