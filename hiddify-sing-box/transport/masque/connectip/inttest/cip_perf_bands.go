//go:build masque_inttest_heavy

package inttest

// Shared CONNECT-IP download bands (in-proc L1 / native session) after P6-D1 bulk ingress.

const (
	h2PerfDownFloor   = 500.0  // SLO ≥70% of ~700 Mbit/s class
	h2PerfDownCeiling = 2500.0 // in-proc sanity upper bound

	h3PerfDownFloor   = 500.0  // H3 local docker class ~900–1100; floor allows host variance
	h3PerfDownCeiling = 2500.0
)
