package stream

import (
	"log"
	"os"
	"strings"
)

// TraceTCPf logs CONNECT-stream TCP diagnostics when MASQUE_TRACE_TCP=1.
func TraceTCPf(format string, args ...any) {
	if strings.TrimSpace(os.Getenv("MASQUE_TRACE_TCP")) != "1" {
		return
	}
	log.Printf(format, args...)
}
