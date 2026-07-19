package masque

import (
	"testing"
	"time"

	"github.com/sagernet/sing-box/transport/masque/connectudp"
)

// TestLocalizeConnectUDPH2BurstTlsTax4us512 logs H2 @512 burst under docker-shaped TLS tax (localize ceiling + zero-loss gate).
func TestLocalizeConnectUDPH2BurstTlsTax4us512(t *testing.T) {
	skipUnlessMasqueBenchLong(t)
	const duration = connectUDPSynthProdBenchDuration
	link := tlsFlushTaxH2Link{Tax: 4 * time.Microsecond}
	mbps, st := benchConnectUDPH2BurstZeroLossMax(t, link, false, duration, connectudp.DefaultBenchUDPPayloadLen)
	t.Logf("LOCALIZE h2 burst tls-tax=4us/4KiB 512B: best-pass=%.1f Mbit/s achieved-ceiling=%.1f loss=%.2f%% rx=%d/%d",
		mbps, connectudp.BurstSinkGoodputMbit(st.RxPkts, connectudp.DefaultBenchUDPPayloadLen, duration.Seconds()), st.LossPct, st.RxPkts, st.SentPkts)
	const ceilingMbps = 320.0
	if mbps > ceilingMbps {
		t.Fatalf("unexpected best-pass above single-stream ceiling %.0f: %.1f Mbit/s", ceilingMbps, mbps)
	}
	// OPEN: paced 500 Mbit/s zero-loss needs architectural fix (PPS ~63k/stream); achieved ~254 matches docker.
}
