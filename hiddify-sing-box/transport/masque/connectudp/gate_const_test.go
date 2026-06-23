package connectudp_test

import (
	"testing"
	"time"

	"github.com/sagernet/sing-box/transport/masque/connectudp"
)

func TestDefaultBenchUDPPayloadLen(t *testing.T) {
	if connectudp.DefaultBenchUDPPayloadLen != 512 {
		t.Fatalf("DefaultBenchUDPPayloadLen=%d want 512", connectudp.DefaultBenchUDPPayloadLen)
	}
}

func TestPaceIntervalZeroTarget(t *testing.T) {
	if got := connectudp.PaceInterval(connectudp.DefaultBenchUDPPayloadLen, 0); got != 0 {
		t.Fatalf("PaceInterval burst=%v want 0", got)
	}
}

func TestPaceSleepUntilCompensatesSendLatency(t *testing.T) {
	const targetMbit = 8.0
	payloadLen := connectudp.DefaultBenchUDPPayloadLen
	interval := connectudp.PaceInterval(payloadLen, targetMbit)
	sendCost := interval / 2

	var slot time.Time
	start := time.Now()
	for range 20 {
		connectudp.PaceSleepUntil(&slot, payloadLen, targetMbit)
		time.Sleep(sendCost)
	}
	elapsed := time.Since(start)
	want := 20 * interval
	tol := interval // scheduler jitter on Windows
	if d := elapsed - want; d < -tol || d > tol {
		t.Fatalf("compensated pacing elapsed=%v want ~%v (tol %v)", elapsed, want, tol)
	}
}
