package server

import (
	"testing"
)

func TestMasqueListenAddrDefaultHost(t *testing.T) {
	t.Parallel()
	if got := MasqueListenAddr("", 8443); got != "0.0.0.0:8443" {
		t.Fatalf("MasqueListenAddr empty host = %q want 0.0.0.0:8443", got)
	}
	if got := MasqueListenAddr("127.0.0.1", 443); got != "127.0.0.1:443" {
		t.Fatalf("MasqueListenAddr explicit host = %q want 127.0.0.1:443", got)
	}
}
