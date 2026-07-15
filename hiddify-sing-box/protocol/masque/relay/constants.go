package relay

// Kernel tuning exported for unit tests and ops introspection.
const (
	// TCPKernelBuf is best-effort SO_SNDBUF for onward TCP dials.
	// Never pair with SetReadBuffer: SO_RCVBUF lock stalls Linux advertised RWND on WAN.
	TCPKernelBuf = 16 << 20
)
