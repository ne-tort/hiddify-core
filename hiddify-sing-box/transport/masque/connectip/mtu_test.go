package connectip

import "testing"

func TestDefaultDatagramCeilingMax(t *testing.T) {
	if DefaultDatagramCeilingMax != 1500 {
		t.Fatalf("got %d want %d", DefaultDatagramCeilingMax, 1500)
	}
	if MaxConfiguredDatagramCeiling != 9000 {
		t.Fatalf("MaxConfiguredDatagramCeiling=%d want 9000", MaxConfiguredDatagramCeiling)
	}
}

func TestH3H2NetstackMTUParity(t *testing.T) {
	ceiling := DefaultDatagramCeilingMax
	h3 := H3NetstackMTU(ceiling)
	h2 := H2NetstackMTU(ceiling)
	if h3 != ceiling-H3FramingSlack {
		t.Fatalf("H3 netstack MTU=%d want %d", h3, ceiling-H3FramingSlack)
	}
	if h2 != ceiling {
		t.Fatalf("H2 netstack MTU=%d want %d", h2, ceiling)
	}
	if h2-h3 != H3FramingSlack {
		t.Fatalf("H2-H3 delta=%d want slack %d", h2-h3, H3FramingSlack)
	}
}

func TestH2MaxCapsulePayloadParity(t *testing.T) {
	ceilingMax := DefaultDatagramCeilingMax
	got := H2MaxCapsulePayload(ceilingMax)
	want := ceilingMax + H3FramingSlack
	if got != want {
		t.Fatalf("H2MaxCapsulePayload=%d want %d", got, want)
	}
	if MaxIPv4Datagram(ceilingMax) != MaxIPv4WireBytes {
		t.Fatalf("MaxIPv4Datagram=%d want wire limit %d", MaxIPv4Datagram(ceilingMax), MaxIPv4WireBytes)
	}
}

// TestP210CeilingDomainLocks locks P2-10 / F4-06: FramingSlack ≠ WireSlack by design.
func TestP210CeilingDomainLocks(t *testing.T) {
	ceiling := DefaultDatagramCeilingMax
	if MaxIPv4WireBytes != ceiling-TCPHTTP3DatagramSlack {
		t.Fatalf("MaxIPv4WireBytes=%d want ceiling-WireSlack=%d", MaxIPv4WireBytes, ceiling-TCPHTTP3DatagramSlack)
	}
	if MaxIPv4WireBytes != 1372 {
		t.Fatalf("MaxIPv4WireBytes=%d want 1372 (behavior-neutral derive)", MaxIPv4WireBytes)
	}
	if TCPHTTP3DatagramSlack != 128 {
		t.Fatalf("WireSlack=%d want 128", TCPHTTP3DatagramSlack)
	}
	if H3FramingSlack != 80 {
		t.Fatalf("FramingSlack=%d want 80", H3FramingSlack)
	}
	if H3FramingSlack == TCPHTTP3DatagramSlack {
		t.Fatal("FramingSlack must not equal WireSlack (distinct domains)")
	}
	h3Link := H3NetstackMTU(ceiling)
	if h3Link != ceiling-H3FramingSlack {
		t.Fatalf("H3NetstackMTU=%d want %d", h3Link, ceiling-H3FramingSlack)
	}
	if h3Link == MaxIPv4WireBytes {
		t.Fatalf("H3NetstackMTU (%d) must not equal MaxIPv4WireBytes (%d) — domains differ", h3Link, MaxIPv4WireBytes)
	}
	if H2MaxCapsulePayload(ceiling) != ceiling+H3FramingSlack {
		t.Fatalf("H2 capsule max=%d want %d", H2MaxCapsulePayload(ceiling), ceiling+H3FramingSlack)
	}
}
