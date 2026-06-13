package server

import (
	"os"
	"strings"
)

// ConnectStreamOnlyServer enables connect-stream-only server mux: CONNECT-UDP/IP stubs, template TCP relay only.
func ConnectStreamOnlyServer() bool {
	for _, key := range []string{"MASQUE_SERVER_THIN", "MASQUE_SERVER_CONNECT_STREAM_ONLY"} {
		switch strings.TrimSpace(strings.ToLower(os.Getenv(key))) {
		case "1", "true", "yes", "on":
			return true
		case "0", "false", "no", "off":
			return false
		}
	}
	return false
}
