//go:build masque_inttest_heavy

package inttest

// P6-D1 post bulk-ingress: shared H2 download bands (in-proc L1 / native session).

const (
	h2PerfDownFloor   = 500.0  // SLO ≥70% of ~700 Mbit/s class
	h2PerfDownCeiling = 2500.0 // in-proc sanity upper bound
)
