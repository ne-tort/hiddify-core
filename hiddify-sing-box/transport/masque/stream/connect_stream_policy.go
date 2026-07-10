package stream

import "os"

const envConnectStreamDualConnect = "MASQUE_CONNECT_STREAM_DUAL_CONNECT"

// ConnectStreamUseDualConnect reports P2 split-legs dial (opt-in; prod default single bidi).
// Set MASQUE_CONNECT_STREAM_DUAL_CONNECT=1 to enable dual CONNECT legs.
func ConnectStreamUseDualConnect() bool {
	switch os.Getenv(envConnectStreamDualConnect) {
	case "1", "true", "yes":
		return true
	default:
		return false
	}
}
