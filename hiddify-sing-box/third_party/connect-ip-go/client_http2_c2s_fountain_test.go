package connectip

import (
	"bytes"
	"testing"
)

type countingPipeWriter struct {
	writes int
	buf    bytes.Buffer
}

func (w *countingPipeWriter) Write(p []byte) (int, error) {
	w.writes++
	return w.buf.Write(p)
}

func TestH2CapsulePipeStreamImplementsCoalescedSender(t *testing.T) {
	var _ proxiedIPDatagramCoalescedSender = (*h2CapsulePipeStream)(nil)
}

func TestH2CapsulePipeStreamSendProxiedIPDatagramWake(t *testing.T) {
	w := &countingPipeWriter{}
	str := &h2CapsulePipeStream{pipeW: w}
	if err := str.SendProxiedIPDatagram(contextIDZero, make([]byte, 40)); err != nil {
		t.Fatal(err)
	}
	if w.writes != 1 {
		t.Fatalf("wake SendProxiedIPDatagram writes=%d want 1", w.writes)
	}
}

func TestH2CapsulePipeStreamC2SVisCoalesce(t *testing.T) {
	w := &countingPipeWriter{}
	str := &h2CapsulePipeStream{pipeW: w}
	for i := 0; i < h2C2SVisMaxPkts-1; i++ {
		if err := str.SendProxiedIPDatagramNoWake(contextIDZero, make([]byte, 40)); err != nil {
			t.Fatalf("NoWake[%d]: %v", i, err)
		}
	}
	if w.writes != 0 {
		t.Fatalf("before threshold writes=%d want 0", w.writes)
	}
	if err := str.SendProxiedIPDatagramNoWake(contextIDZero, make([]byte, 40)); err != nil {
		t.Fatal(err)
	}
	if w.writes != 1 {
		t.Fatalf("at threshold writes=%d want 1", w.writes)
	}
	if err := str.SendProxiedIPDatagramNoWake(contextIDZero, make([]byte, 40)); err != nil {
		t.Fatal(err)
	}
	if w.writes != 1 {
		t.Fatalf("partial batch writes=%d want 1", w.writes)
	}
	str.FlushProxiedIPDatagramSend()
	if w.writes != 2 {
		t.Fatalf("after Flush writes=%d want 2", w.writes)
	}
}

// TestH2CapsulePipeStreamACKWakeDrainsPendingVis: N=16 is safe only if wake path
// never leaves prior NoWake DATA sitting while an ACK waits behind it in pendingVis.
func TestH2CapsulePipeStreamACKWakeDrainsPendingVis(t *testing.T) {
	w := &countingPipeWriter{}
	str := &h2CapsulePipeStream{pipeW: w}
	const pending = 7 // mid-batch under any prod N≥8
	for i := 0; i < pending; i++ {
		if err := str.SendProxiedIPDatagramNoWake(contextIDZero, make([]byte, 800)); err != nil {
			t.Fatalf("NoWake[%d]: %v", i, err)
		}
	}
	if w.writes != 0 {
		t.Fatalf("mid-batch writes=%d want 0", w.writes)
	}
	ack := make([]byte, 40) // small → would be wake at TUN; here exercise wake API
	if err := str.SendProxiedIPDatagram(contextIDZero, ack); err != nil {
		t.Fatal(err)
	}
	// flush pending DATA + write ACK = 2 pipe Writes (DATA then ACK on wire order).
	if w.writes != 2 {
		t.Fatalf("ACK wake writes=%d want 2 (drain pending then ACK)", w.writes)
	}
	if str.pendingVis.Len() != 0 || str.pendingVisPkts != 0 {
		t.Fatalf("pendingVis must be empty after ACK wake")
	}
}

func TestGATEH2UnderlayPipeWritesPerDatagramImmediateWake(t *testing.T) {
	EnableCIPClientRelayStats()
	ResetCIPClientRelayStats()
	w := &countingPipeWriter{}
	str := &h2CapsulePipeStream{pipeW: w}
	const n = 16
	for i := 0; i < n; i++ {
		if err := str.SendProxiedIPDatagram(contextIDZero, make([]byte, 40)); err != nil {
			t.Fatal(err)
		}
	}
	snap := SnapshotCIPClientRelayStats()
	if w.writes != n || snap.H2PipeWrite != uint64(n) {
		t.Fatalf("wake path pipe writes=%d stats=%d want %d (1:1 underlay)", w.writes, snap.H2PipeWrite, n)
	}
}
