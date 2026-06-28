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
