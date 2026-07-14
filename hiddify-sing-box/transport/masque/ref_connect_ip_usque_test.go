package masque

import (
	"testing"
	"time"

	"github.com/sagernet/sing-box/transport/masque/connectip"
)

const refUsqueShapeCeilingMbps = 238.0 // VPS usque CONNECT-IP reference (informational synth ceiling)

// usqueShapeDevice mocks usque MaintainTunnel device pump (ReadPacket/WritePacket, no HTTP CONNECT-stream).
type usqueShapeDevice struct {
	in  chan []byte
	out chan []byte
}

func newUsqueShapeDevice() *usqueShapeDevice {
	return &usqueShapeDevice{
		in:  make(chan []byte, 64),
		out: make(chan []byte, 64),
	}
}

func (d *usqueShapeDevice) ReadPacket(buf []byte) (int, error) {
	select {
	case pkt := <-d.in:
		n := copy(buf, pkt)
		return n, nil
	case <-time.After(50 * time.Millisecond):
		return 0, nil
	}
}

func (d *usqueShapeDevice) WritePacket(pkt []byte) error {
	cp := make([]byte, len(pkt))
	copy(cp, pkt)
	select {
	case d.out <- cp:
	default:
	}
	return nil
}

// TestREFUsqueShapeConnectIPLeg benchmarks usque-shaped WritePacket/ReadPacket loop vs hybrid overhead class.
func TestREFUsqueShapeConnectIPLeg(t *testing.T) {
	mbps := benchRefUsquePumpMbps(connectStreamSynthProdBenchDuration)
	t.Logf("REF-usque-shape pump: %.1f Mbit/s", mbps)
	if mbps < connectStreamSynthProdMinMbps {
		t.Fatalf("REF-usque-shape: %.1f Mbit/s (want >= %.0f in-proc pump floor)", mbps, connectStreamSynthProdMinMbps)
	}
	_ = refUsqueShapeCeilingMbps // informational anchor vs field ~238
}

// TestREFUsqueNetstackPoolAudit verifies connectip inbound frame clone (usque-shaped device pump).
// Arch REF-SRC-USQUE ledger lives under //go:build masque_arch_ledger.
func TestREFUsqueNetstackPoolAudit(t *testing.T) {
	frame := connectip.CloneInboundFrame([]byte{0x45, 0x00, 0x00, 0x1c})
	if len(frame) == 0 {
		t.Fatal("connectip.CloneInboundFrame returned empty")
	}
}

// TestREFConnectIPHybridVsUsqueShape documents synth class: hybrid TCP leg vs usque datagram pump (separate KPI).
func TestREFConnectIPHybridVsUsqueShape(t *testing.T) {
	t.Log("connect-ip hybrid KPI: TestConnectIPHybridConnectStreamH3DownloadKPI (masque_test)")
	t.Log("usque-shaped pump KPI: TestREFUsqueShapeConnectIPLeg (in-proc datagram loop)")
}
