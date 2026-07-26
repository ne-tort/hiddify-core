package forwarder

import "testing"

func TestDynamicRwndEnabled(t *testing.T) {
	t.Setenv("MASQUE_CONNECT_IP_DYNAMIC_RWND", "")
	if dynamicRwndEnabled() {
		t.Fatal("want off")
	}
	t.Setenv("MASQUE_CONNECT_IP_DYNAMIC_RWND", "1")
	if !dynamicRwndEnabled() {
		t.Fatal("want on")
	}
}

func TestAdvertisedWindowDynamicTracksFree(t *testing.T) {
	t.Setenv("MASQUE_CONNECT_IP_DYNAMIC_RWND", "1")
	t.Setenv("MASQUE_CONNECT_IP_C2S_DEPTH", "64")
	s := &tcpForwardSession{
		clientMSS:     1000,
		serverWSScale: 0, // field == bytes when shift 0
		c2sCh:         make(chan []byte, 64),
	}
	// full free → 64*1000 = 64000
	if g := s.advertisedWindowFieldLocked(); g != 64000 {
		t.Fatalf("free all: got %d want 64000", g)
	}
	// occupy 60 slots
	for i := 0; i < 60; i++ {
		s.c2sCh <- []byte{1}
	}
	if g := s.advertisedWindowFieldLocked(); g != 4000 {
		t.Fatalf("free 4: got %d want 4000", g)
	}
}
