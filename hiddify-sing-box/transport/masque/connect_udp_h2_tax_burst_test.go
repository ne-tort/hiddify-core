package masque

import (
	"strconv"
	"testing"
	"time"

	"github.com/sagernet/sing-box/transport/masque/connectudp"
)

// TestLocalizeConnectUDPH2BurstTlsTax4us512 logs H2 @512 burst under docker-shaped TLS tax (localize ceiling + zero-loss gate).
func TestLocalizeConnectUDPH2BurstTlsTax4us512(t *testing.T) {
	const duration = connectUDPSynthProdBenchDuration
	link := tlsFlushTaxH2Link{Tax: 4 * time.Microsecond}
	mbps, st := benchConnectUDPH2BurstZeroLossMax(t, link, false, duration, connectudp.DefaultBenchUDPPayloadLen)
	t.Logf("LOCALIZE h2 burst tls-tax=4us/4KiB 512B: best-pass=%.1f Mbit/s achieved-ceiling=%.1f loss=%.2f%% rx=%d/%d",
		mbps, connectudp.BurstSinkGoodputMbit(st.RxPkts, connectudp.DefaultBenchUDPPayloadLen, duration.Seconds()), st.LossPct, st.RxPkts, st.SentPkts)
	const ceilingMbps = 280.0
	if mbps > ceilingMbps {
		t.Fatalf("unexpected best-pass above single-stream ceiling %.0f: %.1f Mbit/s", ceilingMbps, mbps)
	}
	// OPEN: paced 500 Mbit/s zero-loss needs architectural fix (PPS ~63k/stream); achieved ~254 matches docker.
}

func TestLocalizeConnectUDPH2BurstTlsTax4us512BulkFlushSweep(t *testing.T) {
	const duration = connectUDPSynthProdBenchDuration
	link := tlsFlushTaxH2Link{Tax: 4 * time.Microsecond}
	for _, flushBytes := range []int{-1, 0, 65536, 131072, 262144} {
		if flushBytes >= 0 {
			t.Setenv("MASQUE_H2_UPLOAD_BULK_FLUSH_BYTES", strconv.Itoa(flushBytes))
		} else {
			t.Setenv("MASQUE_H2_UPLOAD_BULK_FLUSH_BYTES", "")
		}
		mbps, _ := benchConnectUDPH2BurstZeroLossMax(t, link, false, duration, connectudp.DefaultBenchUDPPayloadLen)
		label := "default"
		if flushBytes >= 0 {
			label = strconv.Itoa(flushBytes)
		}
		t.Logf("tls-tax=4us bulk-flush-bytes=%s: %.1f Mbit/s", label, mbps)
	}
}
