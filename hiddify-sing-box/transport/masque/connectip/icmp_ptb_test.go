package connectip

import (
	"encoding/binary"
	"testing"
)

func TestParseICMPPTBHopMTUIPv4(t *testing.T) {
	pkt := make([]byte, 28)
	pkt[0] = 0x45
	pkt[9] = 1
	icmpOff := 20
	pkt[icmpOff] = 3
	pkt[icmpOff+1] = 4
	binary.BigEndian.PutUint16(pkt[icmpOff+6:icmpOff+8], 1200)
	mtu, v6, ok := ParseICMPPTBHopMTU(pkt)
	if !ok || v6 || mtu != 1200 {
		t.Fatalf("parse: mtu=%d v6=%v ok=%v", mtu, v6, ok)
	}
}

func TestParseICMPPTBHopMTUIPv6(t *testing.T) {
	pkt := make([]byte, 48)
	pkt[0] = 0x60
	pkt[6] = 58
	icmpOff := 40
	pkt[icmpOff] = 2
	pkt[icmpOff+1] = 0
	binary.BigEndian.PutUint32(pkt[icmpOff+4:icmpOff+8], 1400)
	mtu, v6, ok := ParseICMPPTBHopMTU(pkt)
	if !ok || !v6 || mtu != 1400 {
		t.Fatalf("parse: mtu=%d v6=%v ok=%v", mtu, v6, ok)
	}
}

func TestParseICMPPTBHopMTURejectsInvalid(t *testing.T) {
	if _, _, ok := ParseICMPPTBHopMTU(nil); ok {
		t.Fatal("nil packet should not parse")
	}
	short := []byte{0x45, 0x00}
	if _, _, ok := ParseICMPPTBHopMTU(short); ok {
		t.Fatal("short packet should not parse")
	}
}
