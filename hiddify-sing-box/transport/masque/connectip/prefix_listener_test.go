package connectip

import (
	"net/netip"
	"testing"
)

func TestAssignedPrefixesListenerCallbackSkipsEmpty(t *testing.T) {
	calls := 0
	cb := AssignedPrefixesListenerCallback(func(prefixes []netip.Prefix) {
		calls++
	})
	cb(nil)
	if calls != 0 {
		t.Fatalf("expected 0 calls for empty prefixes, got %d", calls)
	}
}

func TestAssignedPrefixesListenerCallbackInvokesReconcile(t *testing.T) {
	var got []netip.Prefix
	cb := AssignedPrefixesListenerCallback(func(prefixes []netip.Prefix) {
		got = prefixes
	})
	want := []netip.Prefix{netip.MustParsePrefix("10.0.0.2/32")}
	cb(want)
	if len(got) != 1 || got[0] != want[0] {
		t.Fatalf("got %+v want %+v", got, want)
	}
}
