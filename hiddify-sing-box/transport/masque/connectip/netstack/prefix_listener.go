package netstack

import (
	"net/netip"

	cip "github.com/quic-go/connect-ip-go"
)

// PrefixReconcileFunc updates local tunnel addresses after ADDRESS_ASSIGN.
type PrefixReconcileFunc func(prefixes []netip.Prefix)

// AssignedPrefixesListenerCallback returns a connect-ip-go listener that skips empty snapshots.
func AssignedPrefixesListenerCallback(reconcile PrefixReconcileFunc) func([]netip.Prefix) {
	return func(prefixes []netip.Prefix) {
		if len(prefixes) == 0 || reconcile == nil {
			return
		}
		reconcile(prefixes)
	}
}

// RegisterAssignedPrefixesListener wires ADDRESS_ASSIGN updates to reconcile.
func RegisterAssignedPrefixesListener(conn *cip.Conn, reconcile PrefixReconcileFunc) {
	if conn == nil {
		return
	}
	conn.SetAssignedPrefixesListener(AssignedPrefixesListenerCallback(reconcile))
}
