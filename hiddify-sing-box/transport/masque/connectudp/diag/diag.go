package diag

import "log"

// Enabled reports CONNECT-UDP diagnostic logging (build tag masque_debug only).
func Enabled() bool {
	return debugBuild
}

// Logf writes to stderr when Enabled(); no-op in production builds.
func Logf(format string, args ...any) {
	if Enabled() {
		log.Printf(format, args...)
	}
}
