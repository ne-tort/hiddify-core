package server

import (
	"os"
	"strings"
)

// ServerThin enables masque-thin-server parity: CONNECT-UDP/IP stubs, template TCP relay only.
func ServerThin() bool {
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

// ConnectStreamServerOnly is deprecated; use ServerThin.
func ConnectStreamServerOnly() bool {
	return ServerThin()
}

// AuthorityServerMinimal reports whether the MASQUE server should skip CONNECT-UDP/IP mux (thin peer parity).
func AuthorityServerMinimal() bool {
	switch strings.TrimSpace(strings.ToLower(os.Getenv("MASQUE_SERVER_AUTHORITY_MINIMAL"))) {
	case "1", "true", "yes", "on":
		return true
	case "0", "false", "no", "off":
		return false
	default:
		return false
	}
}
