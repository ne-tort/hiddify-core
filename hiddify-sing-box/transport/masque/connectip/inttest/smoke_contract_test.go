package inttest_test

import "testing"

// TestSmokePackageContract documents the default (fast) inttest surface.
// Heavy KPI benches: go test -tags masque_inttest_heavy ./transport/masque/connectip/inttest/ -timeout 600s
func TestSmokePackageContract(t *testing.T) {
	t.Log("connectip inttest default: lifecycle goroutine gates (no masque_inttest_heavy tag)")
}
