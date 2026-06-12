package connectip

import (
	"os"
	"testing"
)

func TestDatagramCeilingMaxEnvContract(t *testing.T) {
	t.Setenv("HIDDIFY_MASQUE_DATAGRAM_CEILING_MAX", "")
	if got := DatagramCeilingMax(); got != DefaultDatagramCeilingMax {
		t.Fatalf("unset: got %d want %d", got, DefaultDatagramCeilingMax)
	}
	t.Setenv("HIDDIFY_MASQUE_DATAGRAM_CEILING_MAX", "4096")
	if got := DatagramCeilingMax(); got != 4096 {
		t.Fatalf("valid override: got %d want 4096", got)
	}
	t.Setenv("HIDDIFY_MASQUE_DATAGRAM_CEILING_MAX", "not-a-number")
	if got := DatagramCeilingMax(); got != DefaultDatagramCeilingMax {
		t.Fatalf("invalid text: got %d want %d", got, DefaultDatagramCeilingMax)
	}
}

func TestH3H2NetstackMTUParity(t *testing.T) {
	ceiling := DefaultDatagramCeilingMax
	h3 := H3NetstackMTU(ceiling)
	h2 := H2NetstackMTU(ceiling)
	if h3 != ceiling-DatagramSlack {
		t.Fatalf("H3 netstack MTU=%d want %d", h3, ceiling-DatagramSlack)
	}
	if h2 != ceiling {
		t.Fatalf("H2 netstack MTU=%d want %d", h2, ceiling)
	}
	if h2-h3 != DatagramSlack {
		t.Fatalf("H2-H3 delta=%d want slack %d", h2-h3, DatagramSlack)
	}
}

func TestH2MaxCapsulePayloadParity(t *testing.T) {
	ceilingMax := DatagramCeilingMax()
	got := H2MaxCapsulePayload(ceilingMax)
	want := ceilingMax + DatagramSlack
	if got != want {
		t.Fatalf("H2MaxCapsulePayload=%d want %d", got, want)
	}
	if MaxIPv4Datagram(ceilingMax)+DatagramSlack != ceilingMax {
		t.Fatalf("MaxIPv4Datagram + slack must equal ceiling max")
	}
}

func TestDatagramCeilingMaxRestoresAfterTest(t *testing.T) {
	prev, ok := os.LookupEnv("HIDDIFY_MASQUE_DATAGRAM_CEILING_MAX")
	t.Cleanup(func() {
		if ok {
			_ = os.Setenv("HIDDIFY_MASQUE_DATAGRAM_CEILING_MAX", prev)
		} else {
			_ = os.Unsetenv("HIDDIFY_MASQUE_DATAGRAM_CEILING_MAX")
		}
	})
}
