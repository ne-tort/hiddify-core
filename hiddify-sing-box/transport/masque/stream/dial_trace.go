package stream

// TraceTCPf is a no-op in prod (MASQUE_TRACE_TCP env removed; bench uses MASQUE_TRACE_TCP=0 in compose only).
func TraceTCPf(string, ...any) {}
