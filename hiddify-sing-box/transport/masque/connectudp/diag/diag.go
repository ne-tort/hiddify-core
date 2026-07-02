package diag

import (
	"log"
	"os"
)

// Enabled reports CONNECT-UDP diagnostic logging (build tag masque_debug or MASQUE_CONNECT_UDP_DEBUG=1).
func Enabled() bool {
	return debugBuild || os.Getenv("MASQUE_CONNECT_UDP_DEBUG") == "1"
}

// Logf writes to stderr when Enabled(); no-op in production builds.
func Logf(format string, args ...any) {
	if Enabled() {
		log.Printf(format, args...)
	}
}
