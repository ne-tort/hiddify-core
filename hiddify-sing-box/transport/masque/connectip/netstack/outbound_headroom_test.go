package netstack

import "testing"

func TestOutboundHeadroomFrame(t *testing.T) {
	ip := borrowOutboundPayload(100)
	for i := range ip {
		ip[i] = byte(i)
	}
	const prefixLen = 5
	frame, ok := FrameFromOutboundIP(ip, prefixLen)
	if !ok {
		t.Fatal("FrameFromOutboundIP: expected ok")
	}
	if len(frame) != prefixLen+len(ip) {
		t.Fatalf("frame len=%d want %d", len(frame), prefixLen+len(ip))
	}
	copy(frame[:prefixLen], []byte{1, 2, 3, 4, 5})
	if frame[prefixLen] != 0 {
		t.Fatalf("IP payload shifted: got %d want 0", frame[prefixLen])
	}
	returnOutboundBuf(ip)
}

func TestReclaimOutboundPoolBuf(t *testing.T) {
	ip := borrowOutboundPayload(64)
	base := reclaimOutboundPoolBuf(ip)
	if base == nil {
		t.Fatal("reclaimOutboundPoolBuf returned nil")
	}
	returnOutboundBuf(ip)
}

func TestBorrowOutboundPayloadHeadroom(t *testing.T) {
	ip := borrowOutboundPayload(64)
	if len(ip) != 64 {
		t.Fatalf("len=%d want 64", len(ip))
	}
	fullCap := cap(ip) + ProxiedIPDatagramHeadroom
	if fullCap < ProxiedIPDatagramHeadroom+64 {
		t.Fatalf("full cap=%d too small", fullCap)
	}
	returnOutboundBuf(ip)
}
