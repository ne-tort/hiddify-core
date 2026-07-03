package netstack

import (
	"testing"
	"time"
)

func TestLocalPrefixWaitProdHardcode(t *testing.T) {
	if got := LocalPrefixWait(); got != defaultLocalPrefixWait {
		t.Fatalf("got %v want prod hardcode %v", got, defaultLocalPrefixWait)
	}
	if defaultLocalPrefixWait != 6*time.Second {
		t.Fatalf("defaultLocalPrefixWait contract: got %v want 6s", defaultLocalPrefixWait)
	}
}
