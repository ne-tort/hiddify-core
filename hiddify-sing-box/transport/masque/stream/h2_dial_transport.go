package stream

// ConnectStreamH2NewTransportPerDial uses a fresh http2.Transport per CONNECT-stream dial (parity
// CONNECT-UDP upload NewTransport). Prod: always on.
func ConnectStreamH2NewTransportPerDial() bool { return true }
