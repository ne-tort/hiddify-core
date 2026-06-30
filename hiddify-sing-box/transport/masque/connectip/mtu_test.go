package connectip

import "testing"

func TestDefaultDatagramCeilingMax(t *testing.T) {
	if DefaultDatagramCeilingMax != 1500 {
		t.Fatalf("got %d want %d", DefaultDatagramCeilingMax, 1500)
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
	if MaxIPv4WireBytes+(DefaultDatagramCeilingMax-MaxIPv4WireBytes) != DefaultDatagramCeilingMax {
		t.Fatalf("wire bytes + wire slack must equal default ceiling")
	}
}
