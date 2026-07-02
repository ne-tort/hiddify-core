package relay

import (
	"io"
	"testing"
)

func TestRelayHTTPDatagramUDPPayloadContextZeroFastPath(t *testing.T) {
	t.Parallel()
	payload, ok, err := relayHTTPDatagramUDPPayload([]byte{0, 'a', 'b'})
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("expected accept")
	}
	if string(payload) != "ab" {
		t.Fatalf("payload=%q want ab", payload)
	}
}

func TestRelayHTTPDatagramUDPPayloadEmptyEOF(t *testing.T) {
	t.Parallel()
	_, ok, err := relayHTTPDatagramUDPPayload(nil)
	if err != io.EOF || ok {
		t.Fatalf("ok=%v err=%v want EOF", ok, err)
	}
}

func TestRelayHTTPDatagramUDPPayloadTwoByteZero(t *testing.T) {
	t.Parallel()
	raw := []byte{0x40, 0x00, 'x'}
	payload, ok, err := relayHTTPDatagramUDPPayload(raw)
	if err != nil {
		t.Fatal(err)
	}
	if !ok || string(payload) != "x" {
		t.Fatalf("ok=%v payload=%q err=%v", ok, payload, err)
	}
}
