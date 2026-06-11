package flowcontrol

import (
	"os"
	"strconv"
	"strings"

	"github.com/quic-go/quic-go/internal/protocol"
)

// windowUpdateThreshold returns the fraction of receive window consumed before MAX_*_DATA.
// MASQUE fat streams default to 0.01 (faster credit return); stock quic-go uses 0.05.
func windowUpdateThreshold() float64 {
	raw := strings.TrimSpace(os.Getenv("MASQUE_QUIC_WINDOW_UPDATE_THRESHOLD"))
	if raw != "" {
		f, err := strconv.ParseFloat(raw, 64)
		if err == nil && f > 0 && f < 1 {
			return f
		}
	}
	if strings.TrimSpace(os.Getenv("MASQUE_QUIC_FAST_WINDOW_UPDATES")) != "0" {
		return 0.01
	}
	return protocol.WindowUpdateThreshold
}
