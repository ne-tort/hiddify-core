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

// H2 C2S NoWake must not hold capsules (P1-1 LEAVE): each NoWake is one pipe write.
func TestH2CapsulePipeStreamC2SNoWakeImmediate(t *testing.T) {
	w := &countingPipeWriter{}
	str := &h2CapsulePipeStream{pipeW: w}
	for i := 0; i < 8; i++ {
		if err := str.SendProxiedIPDatagramNoWake(contextIDZero, make([]byte, 40)); err != nil {
			t.Fatalf("NoWake[%d]: %v", i, err)
		}
	}
	if w.writes != 8 {
		t.Fatalf("NoWake writes=%d want 8 (immediate, no Fountain hold)", w.writes)
	}
	str.FlushProxiedIPDatagramSend()
	if w.writes != 8 {
		t.Fatalf("Flush must be no-op, writes=%d", w.writes)
	}
}
