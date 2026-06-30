package inttest_test

import "testing"

// TestSmokePackageContract documents the default (fast) inttest surface.
// Heavy KPI benches: go test -tags masque_inttest_heavy ./transport/masque/stream/inttest/ -timeout 600s
func TestSmokePackageContract(t *testing.T) {
	t.Log("stream inttest default: H2 socks smoke (no masque_inttest_heavy tag)")
}
