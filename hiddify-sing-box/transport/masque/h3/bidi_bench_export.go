package h3

import "time"

// ExportBenchWindowedBidiLink exposes benchWindowedBidiLink for masque package K-S1 gates.
func ExportBenchWindowedBidiLink() float64 {
	return benchWindowedBidiLink()
}

// ExportBenchWindowedBidiLinkRTT exposes RTT/window-scoped windowed bench for asymmetry gates.
func ExportBenchWindowedBidiLinkRTT(rtt time.Duration, windowBytes int) float64 {
	return benchWindowedBidiLinkRTT(rtt, windowBytes)
}
