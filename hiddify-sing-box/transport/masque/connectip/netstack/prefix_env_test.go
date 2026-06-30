package netstack

import (
	"testing"
	"time"
)

func TestLocalPrefixWaitEnvContract(t *testing.T) {
	run := func(env string, want time.Duration) {
		t.Helper()
		ResetLocalPrefixWaitEnvCache()
		t.Setenv("MASQUE_CONNECT_IP_TCP_NETSTACK_PREFIX_WAIT_SEC", env)
		if got := LocalPrefixWait(); got != want {
			t.Fatalf("env=%q: got %v want %v", env, got, want)
		}
	}
	run("", defaultLocalPrefixWait)
	run("3", 3*time.Second)
	run("not-a-number", defaultLocalPrefixWait)
}
