package stream

import (
	"os"
	"strings"
)

const envH2ConnectStreamNewTransportPerDial = "MASQUE_H2_CONNECT_STREAM_NEW_TRANSPORT_PER_DIAL"

// ConnectStreamH2NewTransportPerDial uses a fresh http2.Transport per CONNECT-stream dial (parity
// CONNECT-UDP upload NewTransport). Bench when shared H2 client pool caps upload on Linux Docker.
func ConnectStreamH2NewTransportPerDial() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(envH2ConnectStreamNewTransportPerDial))) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}
