package frame

import (
	"errors"
	"testing"
)

func TestMaxProxiedUDPPayloadBytesRFC9298(t *testing.T) {
	t.Parallel()
	if MaxProxiedUDPPayloadBytes != 65527 {
		t.Fatalf("MaxProxiedUDPPayloadBytes=%d want 65527", MaxProxiedUDPPayloadBytes)
	}
}

func TestContextIDZeroWireRFC9297(t *testing.T) {
	t.Parallel()
	if len(ContextIDZeroWire) != 1 || ContextIDZeroWire[0] != 0 {
		t.Fatalf("ContextIDZeroWire=%v want [0]", ContextIDZeroWire)
	}
	payload, ok, err := ParseHTTPDatagramUDPFast(append(append([]byte(nil), ContextIDZeroWire...), 'a', 'b'))
	if err != nil || !ok || string(payload) != "ab" {
		t.Fatalf("ParseHTTPDatagramUDPFast(ctx0+ab): payload=%q ok=%v err=%v", payload, ok, err)
	}
}

func TestValidateProxiedUDPPayloadLenRFC9298(t *testing.T) {
	t.Parallel()
	if err := ValidateProxiedUDPPayloadLen(65527); err != nil {
		t.Fatalf("65527: %v", err)
	}
	if err := ValidateProxiedUDPPayloadLen(0); err != nil {
		t.Fatalf("0: %v", err)
	}
	err := ValidateProxiedUDPPayloadLen(65528)
	if !errors.Is(err, ErrProxiedUDPPayloadTooLarge) {
		t.Fatalf("65528: %v want ErrProxiedUDPPayloadTooLarge", err)
	}
}

func TestCheckConnectUDPUDPPayload(t *testing.T) {
	t.Parallel()
	if err := CheckConnectUDPUDPPayload(0, 100); err != nil {
		t.Fatalf("empty: %v", err)
	}
	if err := CheckConnectUDPUDPPayload(100, 100); err != nil {
		t.Fatalf("at product max: %v", err)
	}
	if err := CheckConnectUDPUDPPayload(101, 100); !errors.Is(err, ErrProxiedUDPPayloadTooLarge) {
		t.Fatalf("over product: %v", err)
	}
	if err := CheckConnectUDPUDPPayload(65528, 0); !errors.Is(err, ErrProxiedUDPPayloadTooLarge) {
		t.Fatalf("over RFC: %v", err)
	}
	if err := CheckConnectUDPUDPPayload(65527, 0); err != nil {
		t.Fatalf("RFC max: %v", err)
	}
}

func TestParseHTTPDatagramUDPFastMatchesFullParse(t *testing.T) {
	t.Parallel()
	cases := [][]byte{
		nil,
		{},
		{0, 'h', 'i'},
		{0x40, 0x01},
		{0x80, 0, 0, 0, 0, 'x'},
	}
	for i, data := range cases {
		fastPayload, fastOK, fastErr := ParseHTTPDatagramUDPFast(data)
		fullPayload, fullOK, fullErr := ParseHTTPDatagramUDP(data)
		if fastOK != fullOK || string(fastPayload) != string(fullPayload) {
			t.Fatalf("case %d ok/payload mismatch: fast ok=%v payload=%q full ok=%v payload=%q",
				i, fastOK, fastPayload, fullOK, fullPayload)
		}
		if (fastErr != nil) != (fullErr != nil) {
			t.Fatalf("case %d err mismatch: fast=%v full=%v", i, fastErr, fullErr)
		}
		if fastErr != nil && fullErr != nil && fastErr.Error() != fullErr.Error() {
			t.Fatalf("case %d err text mismatch: fast=%v full=%v", i, fastErr, fullErr)
		}
	}
}
