//go:build ignore
// +build ignore

package l3routerendpoint

import (
	"net/netip"
	"sort"
	"testing"

	rt "github.com/sagernet/sing-box/common/l3router"
	N "github.com/sagernet/sing/common/network"
)

func TestEndpointHotRouteUpdate(t *testing.T) {
	e := &Endpoint{
		engine:   rt.NewMemEngine(),
		peerUser: map[rt.RouteID]string{},
		userRef:  map[rt.SessionKey]int{},
		sessions: map[rt.SessionKey]N.PacketConn{},
	}
	e.enterSession("user-a")
	e.enterSession("user-b")
	t.Cleanup(func() {
		e.leaveSession("user-b")
		e.leaveSession("user-a")
	})

	err := e.UpsertRoute(rt.Route{
		PeerID:          1,
		User:            "user-a",
		FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/24")},
		AllowedIPs:      []netip.Prefix{netip.MustParsePrefix("10.0.0.0/24")},
	})
	if err != nil {
		t.Fatalf("upsert route a: %v", err)
	}
	err = e.UpsertRoute(rt.Route{
		PeerID:          2,
		User:            "user-b",
		FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.0.1.0/24")},
		AllowedIPs:      []netip.Prefix{netip.MustParsePrefix("10.0.1.0/24")},
	})
	if err != nil {
		t.Fatalf("upsert route b: %v", err)
	}

	pktOldDst := makeIPv4([4]byte{10, 0, 0, 2}, [4]byte{10, 0, 1, 2})
	d := e.handleIngressSession(pktOldDst, "user-a")
	if d.Action != rt.ActionForward || d.EgressSession != "user-b" {
		t.Fatalf("initial forward: %+v", d)
	}

	err = e.UpsertRoute(rt.Route{
		PeerID:          2,
		User:            "user-b",
		FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.0.1.0/24")},
		AllowedIPs:      []netip.Prefix{netip.MustParsePrefix("10.0.2.0/24")},
	})
	if err != nil {
		t.Fatalf("update route b: %v", err)
	}

	d = e.handleIngressSession(pktOldDst, "user-a")
	if d.Action != rt.ActionDrop {
		t.Fatalf("old prefix should drop after update: %+v", d)
	}

	pktNewDst := makeIPv4([4]byte{10, 0, 0, 2}, [4]byte{10, 0, 2, 2})
	d = e.handleIngressSession(pktNewDst, "user-a")
	if d.Action != rt.ActionForward || d.EgressSession != "user-b" {
		t.Fatalf("new prefix forward: %+v", d)
	}

	m := e.SnapshotMetrics()
	if m.ControlUpsertOK != 3 || m.ControlErrors != 0 {
		t.Fatalf("metrics mismatch: %+v", m)
	}
}

func TestEndpointControlPlaneErrorMetrics(t *testing.T) {
	e := &Endpoint{
		engine:   rt.NewMemEngine(),
		peerUser: map[rt.RouteID]string{},
		userRef:  map[rt.SessionKey]int{},
		sessions: map[rt.SessionKey]N.PacketConn{},
	}

	err := e.UpsertRoute(rt.Route{
		PeerID: 0,
		User:   "user-a",
	})
	if err == nil {
		t.Fatal("expected validation error")
	}
	e.RemoveRoute(0)

	m := e.SnapshotMetrics()
	if m.ControlUpsertOK != 0 || m.ControlRemoveOK != 0 || m.ControlErrors != 2 {
		t.Fatalf("unexpected metrics: %+v", m)
	}
}

func TestEndpointStaticRouteLoadMetrics(t *testing.T) {
	e := &Endpoint{
		engine:   rt.NewMemEngine(),
		peerUser: map[rt.RouteID]string{},
		userRef:  map[rt.SessionKey]int{},
		sessions: map[rt.SessionKey]N.PacketConn{},
	}

	if err := e.LoadStaticRoute(rt.Route{
		PeerID:          10,
		User:            "user-static",
		FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.9.0.0/24")},
		AllowedIPs:      []netip.Prefix{netip.MustParsePrefix("10.9.0.0/24")},
	}); err != nil {
		t.Fatalf("load static route: %v", err)
	}

	m := e.SnapshotMetrics()
	if m.StaticLoadOK != 1 || m.StaticLoadError != 0 {
		t.Fatalf("unexpected static metrics: %+v", m)
	}
	if m.ControlUpsertOK != 0 || m.ControlErrors != 0 {
		t.Fatalf("control metrics must stay zero for static bootstrap: %+v", m)
	}
}

func TestEndpointRemoveRouteStopsForwarding(t *testing.T) {
	e := &Endpoint{
		engine:   rt.NewMemEngine(),
		peerUser: map[rt.RouteID]string{},
		userRef:  map[rt.SessionKey]int{},
		sessions: map[rt.SessionKey]N.PacketConn{},
	}
	e.enterSession("user-a")
	e.enterSession("user-b")
	t.Cleanup(func() {
		e.leaveSession("user-b")
		e.leaveSession("user-a")
	})

	if err := e.UpsertRoute(rt.Route{
		PeerID:          1,
		User:            "user-a",
		FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/24")},
		AllowedIPs:      []netip.Prefix{netip.MustParsePrefix("10.0.0.0/24")},
	}); err != nil {
		t.Fatalf("upsert route a: %v", err)
	}
	if err := e.UpsertRoute(rt.Route{
		PeerID:          2,
		User:            "user-b",
		FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.0.1.0/24")},
		AllowedIPs:      []netip.Prefix{netip.MustParsePrefix("10.0.1.0/24")},
	}); err != nil {
		t.Fatalf("upsert route b: %v", err)
	}

	pkt := makeIPv4([4]byte{10, 0, 0, 2}, [4]byte{10, 0, 1, 2})
	d := e.handleIngressSession(pkt, "user-a")
	if d.Action != rt.ActionForward || d.EgressSession != "user-b" {
		t.Fatalf("forward before remove: %+v", d)
	}

	e.RemoveRoute(2)
	d = e.handleIngressSession(pkt, "user-a")
	if d.Action != rt.ActionDrop {
		t.Fatalf("expected drop after remove, got %+v", d)
	}

	m := e.SnapshotMetrics()
	if m.ControlUpsertOK != 2 || m.ControlRemoveOK != 1 || m.ControlErrors != 0 {
		t.Fatalf("unexpected metrics after remove: %+v", m)
	}
}

func TestEndpointOwnerChangeRebindsSessions(t *testing.T) {
	e := &Endpoint{
		engine:   rt.NewMemEngine(),
		peerUser: map[rt.RouteID]string{},
		userRef:  map[rt.SessionKey]int{},
		sessions: map[rt.SessionKey]N.PacketConn{},
	}
	e.enterSession("user-a")
	e.enterSession("user-b")
	e.enterSession("user-c")
	t.Cleanup(func() {
		e.leaveSession("user-c")
		e.leaveSession("user-b")
		e.leaveSession("user-a")
	})

	if err := e.UpsertRoute(rt.Route{
		PeerID:          1,
		User:            "user-a",
		FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/24")},
		AllowedIPs:      []netip.Prefix{netip.MustParsePrefix("10.0.0.0/24")},
	}); err != nil {
		t.Fatalf("upsert route 1: %v", err)
	}
	if err := e.UpsertRoute(rt.Route{
		PeerID:          2,
		User:            "user-c",
		FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.0.2.0/24")},
		AllowedIPs:      []netip.Prefix{netip.MustParsePrefix("10.0.2.0/24")},
	}); err != nil {
		t.Fatalf("upsert route 2: %v", err)
	}

	pktFromA := makeIPv4([4]byte{10, 0, 0, 2}, [4]byte{10, 0, 2, 2})
	d := e.handleIngressSession(pktFromA, "user-a")
	if d.Action != rt.ActionForward || d.EgressSession != "user-c" {
		t.Fatalf("forward with initial owner failed: %+v", d)
	}

	if err := e.UpsertRoute(rt.Route{
		PeerID:          1,
		User:            "user-b",
		FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.0.1.0/24")},
		AllowedIPs:      []netip.Prefix{netip.MustParsePrefix("10.0.1.0/24")},
	}); err != nil {
		t.Fatalf("re-upsert route 1 with new owner: %v", err)
	}

	d = e.handleIngressSession(pktFromA, "user-a")
	if d.Action != rt.ActionDrop {
		t.Fatalf("old owner must be unbound after owner change, got %+v", d)
	}

	pktFromB := makeIPv4([4]byte{10, 0, 1, 2}, [4]byte{10, 0, 2, 2})
	d = e.handleIngressSession(pktFromB, "user-b")
	if d.Action != rt.ActionForward || d.EgressSession != "user-c" {
		t.Fatalf("new owner must forward after rebind: %+v", d)
	}
}

func TestEndpointOwnerChangeWithoutNewSessionDropsTraffic(t *testing.T) {
	e := &Endpoint{
		engine:   rt.NewMemEngine(),
		peerUser: map[rt.RouteID]string{},
		userRef:  map[rt.SessionKey]int{},
		sessions: map[rt.SessionKey]N.PacketConn{},
	}
	e.enterSession("user-a")
	e.enterSession("user-c")
	t.Cleanup(func() {
		e.leaveSession("user-c")
		e.leaveSession("user-a")
	})

	if err := e.UpsertRoute(rt.Route{
		PeerID:          1,
		User:            "user-a",
		FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/24")},
		AllowedIPs:      []netip.Prefix{netip.MustParsePrefix("10.0.0.0/24")},
	}); err != nil {
		t.Fatalf("upsert route 1: %v", err)
	}
	if err := e.UpsertRoute(rt.Route{
		PeerID:          2,
		User:            "user-c",
		FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.0.2.0/24")},
		AllowedIPs:      []netip.Prefix{netip.MustParsePrefix("10.0.2.0/24")},
	}); err != nil {
		t.Fatalf("upsert route 2: %v", err)
	}

	pktFromA := makeIPv4([4]byte{10, 0, 0, 2}, [4]byte{10, 0, 2, 2})
	if d := e.handleIngressSession(pktFromA, "user-a"); d.Action != rt.ActionForward {
		t.Fatalf("forward with initial owner failed: %+v", d)
	}

	if err := e.UpsertRoute(rt.Route{
		PeerID:          1,
		User:            "user-b",
		FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.0.1.0/24")},
		AllowedIPs:      []netip.Prefix{netip.MustParsePrefix("10.0.1.0/24")},
	}); err != nil {
		t.Fatalf("re-upsert route 1 with offline owner: %v", err)
	}

	d := e.handleIngressSession(pktFromA, "user-a")
	if d.Action != rt.ActionDrop {
		t.Fatalf("old owner must be fully unbound while new owner session is absent, got %+v", d)
	}
}

func TestEndpointOwnerChangeChainRebindsAndDropsStaleOwners(t *testing.T) {
	e := &Endpoint{
		engine:   rt.NewMemEngine(),
		peerUser: map[rt.RouteID]string{},
		userRef:  map[rt.SessionKey]int{},
		sessions: map[rt.SessionKey]N.PacketConn{},
	}
	e.enterSession("user-a")
	e.enterSession("user-b")
	e.enterSession("user-c")
	e.enterSession("user-z")
	t.Cleanup(func() {
		e.leaveSession("user-z")
		e.leaveSession("user-c")
		e.leaveSession("user-b")
		e.leaveSession("user-a")
	})

	if err := e.UpsertRoute(rt.Route{
		PeerID:          1,
		User:            "user-a",
		FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/24")},
		AllowedIPs:      []netip.Prefix{netip.MustParsePrefix("10.0.0.0/24")},
	}); err != nil {
		t.Fatalf("upsert route 1 as user-a: %v", err)
	}
	if err := e.UpsertRoute(rt.Route{
		PeerID:          2,
		User:            "user-z",
		FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.0.9.0/24")},
		AllowedIPs:      []netip.Prefix{netip.MustParsePrefix("10.0.9.0/24")},
	}); err != nil {
		t.Fatalf("upsert route 2: %v", err)
	}

	assertDrop := func(pkt []byte, session string, msg string) {
		t.Helper()
		if d := e.handleIngressSession(pkt, rt.SessionKey(session)); d.Action != rt.ActionDrop {
			t.Fatalf("%s: expected drop, got %+v", msg, d)
		}
	}
	assertForward := func(pkt []byte, session string, wantEgress string, msg string) {
		t.Helper()
		d := e.handleIngressSession(pkt, rt.SessionKey(session))
		if d.Action != rt.ActionForward || d.EgressSession != rt.SessionKey(wantEgress) {
			t.Fatalf("%s: expected forward to %s, got %+v", msg, wantEgress, d)
		}
	}

	// A -> Z works initially.
	pktFromA := makeIPv4([4]byte{10, 0, 0, 5}, [4]byte{10, 0, 9, 9})
	assertForward(pktFromA, "user-a", "user-z", "initial owner A")

	// Move owner A -> B.
	if err := e.UpsertRoute(rt.Route{
		PeerID:          1,
		User:            "user-b",
		FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.0.1.0/24")},
		AllowedIPs:      []netip.Prefix{netip.MustParsePrefix("10.0.1.0/24")},
	}); err != nil {
		t.Fatalf("re-upsert route 1 as user-b: %v", err)
	}
	assertDrop(pktFromA, "user-a", "stale owner A after A->B")
	pktFromB := makeIPv4([4]byte{10, 0, 1, 5}, [4]byte{10, 0, 9, 9})
	assertForward(pktFromB, "user-b", "user-z", "new owner B after A->B")

	// Move owner B -> C.
	if err := e.UpsertRoute(rt.Route{
		PeerID:          1,
		User:            "user-c",
		FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.0.2.0/24")},
		AllowedIPs:      []netip.Prefix{netip.MustParsePrefix("10.0.2.0/24")},
	}); err != nil {
		t.Fatalf("re-upsert route 1 as user-c: %v", err)
	}
	assertDrop(pktFromB, "user-b", "stale owner B after B->C")
	pktFromC := makeIPv4([4]byte{10, 0, 2, 5}, [4]byte{10, 0, 9, 9})
	assertForward(pktFromC, "user-c", "user-z", "new owner C after B->C")

	m := e.SnapshotMetrics()
	if m.ControlUpsertOK != 4 || m.ControlErrors != 0 {
		t.Fatalf("unexpected metrics on owner change chain: %+v", m)
	}
}

func TestEndpointHotUpdateUpsertRemoveSequence(t *testing.T) {
	e := &Endpoint{
		engine:   rt.NewMemEngine(),
		peerUser: map[rt.RouteID]string{},
		userRef:  map[rt.SessionKey]int{},
		sessions: map[rt.SessionKey]N.PacketConn{},
	}
	e.enterSession("user-a")
	e.enterSession("user-b")
	e.enterSession("user-c")
	t.Cleanup(func() {
		e.leaveSession("user-c")
		e.leaveSession("user-b")
		e.leaveSession("user-a")
	})

	mustUpsert := func(r rt.Route) {
		t.Helper()
		if err := e.UpsertRoute(r); err != nil {
			t.Fatalf("upsert peer %d (%s): %v", r.PeerID, r.User, err)
		}
	}
	mustForward := func(pkt []byte, ingress, wantEgress string) {
		t.Helper()
		d := e.handleIngressSession(pkt, rt.SessionKey(ingress))
		if d.Action != rt.ActionForward || d.EgressSession != rt.SessionKey(wantEgress) {
			t.Fatalf("expected %s -> %s forward, got %+v", ingress, wantEgress, d)
		}
	}
	mustDrop := func(pkt []byte, ingress string) {
		t.Helper()
		if d := e.handleIngressSession(pkt, rt.SessionKey(ingress)); d.Action != rt.ActionDrop {
			t.Fatalf("expected %s drop, got %+v", ingress, d)
		}
	}

	mustUpsert(rt.Route{
		PeerID:          1,
		User:            "user-a",
		FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/24")},
		AllowedIPs:      []netip.Prefix{netip.MustParsePrefix("10.0.0.0/24")},
	})
	mustUpsert(rt.Route{
		PeerID:          2,
		User:            "user-b",
		FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.0.1.0/24")},
		AllowedIPs:      []netip.Prefix{netip.MustParsePrefix("10.0.1.0/24")},
	})
	pktAtoB := makeIPv4([4]byte{10, 0, 0, 10}, [4]byte{10, 0, 1, 20})
	mustForward(pktAtoB, "user-a", "user-b")

	// remove B route: dataplane must stop immediately.
	e.RemoveRoute(2)
	mustDrop(pktAtoB, "user-a")

	// upsert C route to same destination prefix: forwarding must switch A->C.
	mustUpsert(rt.Route{
		PeerID:          3,
		User:            "user-c",
		FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.0.2.0/24")},
		AllowedIPs:      []netip.Prefix{netip.MustParsePrefix("10.0.1.0/24")},
	})
	mustForward(pktAtoB, "user-a", "user-c")

	// owner hot-update for route 1: stale A must drop, B becomes ingress owner.
	mustUpsert(rt.Route{
		PeerID:          1,
		User:            "user-b",
		FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.0.1.0/24")},
		AllowedIPs:      []netip.Prefix{netip.MustParsePrefix("10.0.0.0/24")},
	})
	mustDrop(pktAtoB, "user-a")
	pktBtoPeer := makeIPv4([4]byte{10, 0, 1, 10}, [4]byte{10, 0, 1, 20})
	mustForward(pktBtoPeer, "user-b", "user-c")

	m := e.SnapshotMetrics()
	if m.ControlUpsertOK != 4 || m.ControlRemoveOK != 1 || m.ControlErrors != 0 {
		t.Fatalf("unexpected metrics on upsert/remove sequence: %+v", m)
	}
}

func TestEndpointRemoveAndReAddRouteBindsOnlyNewOwner(t *testing.T) {
	e := &Endpoint{
		engine:   rt.NewMemEngine(),
		peerUser: map[rt.RouteID]string{},
		userRef:  map[rt.SessionKey]int{},
		sessions: map[rt.SessionKey]N.PacketConn{},
	}
	e.enterSession("user-a")
	e.enterSession("user-b")
	e.enterSession("user-c")
	t.Cleanup(func() {
		e.leaveSession("user-c")
		e.leaveSession("user-b")
		e.leaveSession("user-a")
	})

	mustUpsert := func(r rt.Route) {
		t.Helper()
		if err := e.UpsertRoute(r); err != nil {
			t.Fatalf("upsert peer %d (%s): %v", r.PeerID, r.User, err)
		}
	}
	mustForward := func(pkt []byte, ingress, wantEgress string) {
		t.Helper()
		d := e.handleIngressSession(pkt, rt.SessionKey(ingress))
		if d.Action != rt.ActionForward || d.EgressSession != rt.SessionKey(wantEgress) {
			t.Fatalf("expected %s -> %s forward, got %+v", ingress, wantEgress, d)
		}
	}
	mustDrop := func(pkt []byte, ingress string) {
		t.Helper()
		if d := e.handleIngressSession(pkt, rt.SessionKey(ingress)); d.Action != rt.ActionDrop {
			t.Fatalf("expected %s drop, got %+v", ingress, d)
		}
	}

	mustUpsert(rt.Route{
		PeerID:          1,
		User:            "user-a",
		FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/24")},
		AllowedIPs:      []netip.Prefix{netip.MustParsePrefix("10.0.0.0/24")},
	})
	mustUpsert(rt.Route{
		PeerID:          2,
		User:            "user-b",
		FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.0.1.0/24")},
		AllowedIPs:      []netip.Prefix{netip.MustParsePrefix("10.0.1.0/24")},
	})
	pktAtoB := makeIPv4([4]byte{10, 0, 0, 9}, [4]byte{10, 0, 1, 9})
	mustForward(pktAtoB, "user-a", "user-b")

	e.RemoveRoute(2)
	mustDrop(pktAtoB, "user-a")

	mustUpsert(rt.Route{
		PeerID:          2,
		User:            "user-c",
		FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.0.2.0/24")},
		AllowedIPs:      []netip.Prefix{netip.MustParsePrefix("10.0.1.0/24")},
	})
	mustForward(pktAtoB, "user-a", "user-c")

	pktCtoA := makeIPv4([4]byte{10, 0, 2, 9}, [4]byte{10, 0, 0, 9})
	mustForward(pktCtoA, "user-c", "user-a")

	// Removed owner must not remain bound after route re-add.
	pktBtoA := makeIPv4([4]byte{10, 0, 1, 9}, [4]byte{10, 0, 0, 9})
	mustDrop(pktBtoA, "user-b")
}

func TestEndpointOwnerFlipFlopRebindsWithoutStaleIngress(t *testing.T) {
	e := &Endpoint{
		engine:   rt.NewMemEngine(),
		peerUser: map[rt.RouteID]string{},
		userRef:  map[rt.SessionKey]int{},
		sessions: map[rt.SessionKey]N.PacketConn{},
	}
	e.enterSession("user-a")
	e.enterSession("user-b")
	e.enterSession("user-z")
	t.Cleanup(func() {
		e.leaveSession("user-z")
		e.leaveSession("user-b")
		e.leaveSession("user-a")
	})

	if err := e.UpsertRoute(rt.Route{
		PeerID:          1,
		User:            "user-a",
		FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/24")},
		AllowedIPs:      []netip.Prefix{netip.MustParsePrefix("10.0.0.0/24")},
	}); err != nil {
		t.Fatalf("upsert route 1: %v", err)
	}
	if err := e.UpsertRoute(rt.Route{
		PeerID:          9,
		User:            "user-z",
		FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.0.9.0/24")},
		AllowedIPs:      []netip.Prefix{netip.MustParsePrefix("10.0.9.0/24")},
	}); err != nil {
		t.Fatalf("upsert route 9: %v", err)
	}

	assertForward := func(pkt []byte, ingress, wantEgress string) {
		t.Helper()
		d := e.handleIngressSession(pkt, rt.SessionKey(ingress))
		if d.Action != rt.ActionForward || d.EgressSession != rt.SessionKey(wantEgress) {
			t.Fatalf("expected %s -> %s forward, got %+v", ingress, wantEgress, d)
		}
	}
	assertDrop := func(pkt []byte, ingress string) {
		t.Helper()
		if d := e.handleIngressSession(pkt, rt.SessionKey(ingress)); d.Action != rt.ActionDrop {
			t.Fatalf("expected %s drop, got %+v", ingress, d)
		}
	}

	pktFromA := makeIPv4([4]byte{10, 0, 0, 12}, [4]byte{10, 0, 9, 77})
	pktFromB := makeIPv4([4]byte{10, 0, 1, 12}, [4]byte{10, 0, 9, 77})

	assertForward(pktFromA, "user-a", "user-z")
	if err := e.UpsertRoute(rt.Route{
		PeerID:          1,
		User:            "user-b",
		FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.0.1.0/24")},
		AllowedIPs:      []netip.Prefix{netip.MustParsePrefix("10.0.1.0/24")},
	}); err != nil {
		t.Fatalf("owner change A->B failed: %v", err)
	}
	assertDrop(pktFromA, "user-a")
	assertForward(pktFromB, "user-b", "user-z")

	// Flip back B->A and verify stale B is removed.
	if err := e.UpsertRoute(rt.Route{
		PeerID:          1,
		User:            "user-a",
		FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/24")},
		AllowedIPs:      []netip.Prefix{netip.MustParsePrefix("10.0.0.0/24")},
	}); err != nil {
		t.Fatalf("owner change B->A failed: %v", err)
	}
	assertDrop(pktFromB, "user-b")
	assertForward(pktFromA, "user-a", "user-z")
}

func TestEndpointOwnerChangeChainWithOfflineMiddleOwner(t *testing.T) {
	e := &Endpoint{
		engine:   rt.NewMemEngine(),
		peerUser: map[rt.RouteID]string{},
		userRef:  map[rt.SessionKey]int{},
		sessions: map[rt.SessionKey]N.PacketConn{},
	}
	e.enterSession("user-a")
	e.enterSession("user-c")
	e.enterSession("user-z")
	t.Cleanup(func() {
		e.leaveSession("user-z")
		e.leaveSession("user-c")
		e.leaveSession("user-a")
	})

	mustUpsert := func(r rt.Route) {
		t.Helper()
		if err := e.UpsertRoute(r); err != nil {
			t.Fatalf("upsert peer %d (%s): %v", r.PeerID, r.User, err)
		}
	}
	mustDrop := func(pkt []byte, ingress string) {
		t.Helper()
		if d := e.handleIngressSession(pkt, rt.SessionKey(ingress)); d.Action != rt.ActionDrop {
			t.Fatalf("expected %s drop, got %+v", ingress, d)
		}
	}
	mustForward := func(pkt []byte, ingress, wantEgress string) {
		t.Helper()
		d := e.handleIngressSession(pkt, rt.SessionKey(ingress))
		if d.Action != rt.ActionForward || d.EgressSession != rt.SessionKey(wantEgress) {
			t.Fatalf("expected %s -> %s forward, got %+v", ingress, wantEgress, d)
		}
	}

	mustUpsert(rt.Route{
		PeerID:          1,
		User:            "user-a",
		FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/24")},
		AllowedIPs:      []netip.Prefix{netip.MustParsePrefix("10.0.0.0/24")},
	})
	mustUpsert(rt.Route{
		PeerID:          9,
		User:            "user-z",
		FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.0.9.0/24")},
		AllowedIPs:      []netip.Prefix{netip.MustParsePrefix("10.0.9.0/24")},
	})

	pktFromA := makeIPv4([4]byte{10, 0, 0, 15}, [4]byte{10, 0, 9, 99})
	mustForward(pktFromA, "user-a", "user-z")

	// A -> B (offline): stale A must drop, but no new forwarding until owner C appears.
	mustUpsert(rt.Route{
		PeerID:          1,
		User:            "user-b",
		FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.0.1.0/24")},
		AllowedIPs:      []netip.Prefix{netip.MustParsePrefix("10.0.1.0/24")},
	})
	mustDrop(pktFromA, "user-a")

	// B (offline) -> C (online): C must forward, stale A remains dropped.
	mustUpsert(rt.Route{
		PeerID:          1,
		User:            "user-c",
		FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.0.2.0/24")},
		AllowedIPs:      []netip.Prefix{netip.MustParsePrefix("10.0.2.0/24")},
	})
	mustDrop(pktFromA, "user-a")
	pktFromC := makeIPv4([4]byte{10, 0, 2, 15}, [4]byte{10, 0, 9, 99})
	mustForward(pktFromC, "user-c", "user-z")

	m := e.SnapshotMetrics()
	if m.ControlUpsertOK != 4 || m.ControlErrors != 0 {
		t.Fatalf("unexpected metrics in offline-middle-owner chain: %+v", m)
	}
}

func TestEndpointOwnerChangeChainAvoidsSelfLoopOnCompetingPrefix(t *testing.T) {
	e := &Endpoint{
		engine:   rt.NewMemEngine(),
		peerUser: map[rt.RouteID]string{},
		userRef:  map[rt.SessionKey]int{},
		sessions: map[rt.SessionKey]N.PacketConn{},
	}
	e.enterSession("user-a")
	e.enterSession("user-b")
	e.enterSession("user-c")
	e.enterSession("user-z")
	t.Cleanup(func() {
		e.leaveSession("user-z")
		e.leaveSession("user-c")
		e.leaveSession("user-b")
		e.leaveSession("user-a")
	})

	mustUpsert := func(r rt.Route) {
		t.Helper()
		if err := e.UpsertRoute(r); err != nil {
			t.Fatalf("upsert peer %d (%s): %v", r.PeerID, r.User, err)
		}
	}
	mustForward := func(pkt []byte, ingress, wantEgress string) {
		t.Helper()
		d := e.handleIngressSession(pkt, rt.SessionKey(ingress))
		if d.Action != rt.ActionForward || d.EgressSession != rt.SessionKey(wantEgress) {
			t.Fatalf("expected %s -> %s forward, got %+v", ingress, wantEgress, d)
		}
	}
	mustDrop := func(pkt []byte, ingress string) {
		t.Helper()
		if d := e.handleIngressSession(pkt, rt.SessionKey(ingress)); d.Action != rt.ActionDrop {
			t.Fatalf("expected %s drop, got %+v", ingress, d)
		}
	}

	mustUpsert(rt.Route{
		PeerID:          1,
		User:            "user-a",
		FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/24")},
		AllowedIPs:      []netip.Prefix{netip.MustParsePrefix("10.0.9.0/24")},
	})
	mustUpsert(rt.Route{
		PeerID:          9,
		User:            "user-z",
		FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.0.9.0/24")},
		AllowedIPs:      []netip.Prefix{netip.MustParsePrefix("10.0.9.0/24")},
	})

	pktFromA := makeIPv4([4]byte{10, 0, 0, 25}, [4]byte{10, 0, 9, 99})
	mustForward(pktFromA, "user-a", "user-z")

	mustUpsert(rt.Route{
		PeerID:          1,
		User:            "user-b",
		FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.0.1.0/24")},
		AllowedIPs:      []netip.Prefix{netip.MustParsePrefix("10.0.9.0/24")},
	})
	mustDrop(pktFromA, "user-a")
	pktFromB := makeIPv4([4]byte{10, 0, 1, 25}, [4]byte{10, 0, 9, 99})
	mustForward(pktFromB, "user-b", "user-z")

	mustUpsert(rt.Route{
		PeerID:          1,
		User:            "user-c",
		FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.0.2.0/24")},
		AllowedIPs:      []netip.Prefix{netip.MustParsePrefix("10.0.9.0/24")},
	})
	mustDrop(pktFromB, "user-b")
	pktFromC := makeIPv4([4]byte{10, 0, 2, 25}, [4]byte{10, 0, 9, 99})
	mustForward(pktFromC, "user-c", "user-z")

	m := e.SnapshotMetrics()
	if m.ControlUpsertOK != 4 || m.ControlErrors != 0 {
		t.Fatalf("unexpected metrics in owner loop-avoid chain: %+v", m)
	}
}

func TestEndpointOwnerChainAtoBtoCRemovesStaleIngressAndKeepsNonLoopEgress(t *testing.T) {
	e := &Endpoint{
		engine:   rt.NewMemEngine(),
		peerUser: map[rt.RouteID]string{},
		userRef:  map[rt.SessionKey]int{},
		sessions: map[rt.SessionKey]N.PacketConn{},
	}
	e.enterSession("user-a")
	e.enterSession("user-b")
	e.enterSession("user-c")
	e.enterSession("user-z")
	t.Cleanup(func() {
		e.leaveSession("user-z")
		e.leaveSession("user-c")
		e.leaveSession("user-b")
		e.leaveSession("user-a")
	})

	mustUpsert := func(r rt.Route) {
		t.Helper()
		if err := e.UpsertRoute(r); err != nil {
			t.Fatalf("upsert peer %d (%s): %v", r.PeerID, r.User, err)
		}
	}
	mustDrop := func(pkt []byte, ingress string) {
		t.Helper()
		if d := e.handleIngressSession(pkt, rt.SessionKey(ingress)); d.Action != rt.ActionDrop {
			t.Fatalf("expected %s drop, got %+v", ingress, d)
		}
	}
	mustForward := func(pkt []byte, ingress, wantEgress string) {
		t.Helper()
		d := e.handleIngressSession(pkt, rt.SessionKey(ingress))
		if d.Action != rt.ActionForward || d.EgressSession != rt.SessionKey(wantEgress) {
			t.Fatalf("expected %s -> %s forward, got %+v", ingress, wantEgress, d)
		}
	}

	mustUpsert(rt.Route{
		PeerID:          1,
		User:            "user-a",
		FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/24")},
		AllowedIPs:      []netip.Prefix{netip.MustParsePrefix("10.0.0.0/24")},
	})
	mustUpsert(rt.Route{
		PeerID:          9,
		User:            "user-z",
		FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.0.9.0/24")},
		AllowedIPs:      []netip.Prefix{netip.MustParsePrefix("10.0.9.0/24")},
	})
	pktAtoZ := makeIPv4([4]byte{10, 0, 0, 44}, [4]byte{10, 0, 9, 44})
	pktBtoZ := makeIPv4([4]byte{10, 0, 1, 44}, [4]byte{10, 0, 9, 44})
	pktCtoZ := makeIPv4([4]byte{10, 0, 2, 44}, [4]byte{10, 0, 9, 44})
	mustForward(pktAtoZ, "user-a", "user-z")

	mustUpsert(rt.Route{
		PeerID:          1,
		User:            "user-b",
		FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.0.1.0/24")},
		AllowedIPs:      []netip.Prefix{netip.MustParsePrefix("10.0.1.0/24")},
	})
	mustDrop(pktAtoZ, "user-a")
	mustForward(pktBtoZ, "user-b", "user-z")

	mustUpsert(rt.Route{
		PeerID:          1,
		User:            "user-c",
		FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.0.2.0/24")},
		AllowedIPs:      []netip.Prefix{netip.MustParsePrefix("10.0.2.0/24")},
	})
	mustDrop(pktBtoZ, "user-b")
	mustForward(pktCtoZ, "user-c", "user-z")

	m := e.SnapshotMetrics()
	if m.ControlUpsertOK != 4 || m.ControlErrors != 0 {
		t.Fatalf("unexpected metrics in A->B->C owner chain: %+v", m)
	}
}

func TestEndpointOwnerChangeChainWithCompetingPeerPrefixNeverSelectsLoopback(t *testing.T) {
	e := &Endpoint{
		engine:   rt.NewMemEngine(),
		peerUser: map[rt.RouteID]string{},
		userRef:  map[rt.SessionKey]int{},
		sessions: map[rt.SessionKey]N.PacketConn{},
	}
	e.enterSession("user-a")
	e.enterSession("user-b")
	e.enterSession("user-c")
	e.enterSession("user-z")
	t.Cleanup(func() {
		e.leaveSession("user-z")
		e.leaveSession("user-c")
		e.leaveSession("user-b")
		e.leaveSession("user-a")
	})

	mustUpsert := func(r rt.Route) {
		t.Helper()
		if err := e.UpsertRoute(r); err != nil {
			t.Fatalf("upsert peer %d (%s): %v", r.PeerID, r.User, err)
		}
	}
	assertForwardNonLoop := func(pkt []byte, ingress, forbiddenEgress string) {
		t.Helper()
		d := e.handleIngressSession(pkt, rt.SessionKey(ingress))
		if d.Action != rt.ActionForward {
			t.Fatalf("expected %s forward, got %+v", ingress, d)
		}
		if d.EgressSession == rt.SessionKey(forbiddenEgress) {
			t.Fatalf("loopback detected for %s: %+v", ingress, d)
		}
	}
	assertDrop := func(pkt []byte, ingress string) {
		t.Helper()
		if d := e.handleIngressSession(pkt, rt.SessionKey(ingress)); d.Action != rt.ActionDrop {
			t.Fatalf("expected %s drop, got %+v", ingress, d)
		}
	}

	mustUpsert(rt.Route{
		PeerID:          1,
		User:            "user-a",
		FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/24")},
		AllowedIPs:      []netip.Prefix{netip.MustParsePrefix("10.0.9.0/24")},
	})
	mustUpsert(rt.Route{
		PeerID:          2,
		User:            "user-z",
		FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.0.9.0/24")},
		AllowedIPs:      []netip.Prefix{netip.MustParsePrefix("10.0.9.0/24")},
	})
	mustUpsert(rt.Route{
		PeerID:          3,
		User:            "user-b",
		FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.0.1.0/24")},
		AllowedIPs:      []netip.Prefix{netip.MustParsePrefix("10.0.9.0/24")},
	})

	pktA := makeIPv4([4]byte{10, 0, 0, 55}, [4]byte{10, 0, 9, 55})
	assertForwardNonLoop(pktA, "user-a", "user-a")

	mustUpsert(rt.Route{
		PeerID:          1,
		User:            "user-b",
		FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.0.1.0/24")},
		AllowedIPs:      []netip.Prefix{netip.MustParsePrefix("10.0.9.0/24")},
	})
	assertDrop(pktA, "user-a")
	pktB := makeIPv4([4]byte{10, 0, 1, 55}, [4]byte{10, 0, 9, 55})
	assertForwardNonLoop(pktB, "user-b", "user-b")

	mustUpsert(rt.Route{
		PeerID:          1,
		User:            "user-c",
		FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.0.2.0/24")},
		AllowedIPs:      []netip.Prefix{netip.MustParsePrefix("10.0.9.0/24")},
	})
	assertDrop(pktB, "user-b")
	pktC := makeIPv4([4]byte{10, 0, 2, 55}, [4]byte{10, 0, 9, 55})
	assertForwardNonLoop(pktC, "user-c", "user-c")
}

func TestEndpointOwnerChangeAtoBThenAtoCWithCompetingPrefixKeepsAuthPathStable(t *testing.T) {
	e := &Endpoint{
		engine:   rt.NewMemEngine(),
		peerUser: map[rt.RouteID]string{},
		userRef:  map[rt.SessionKey]int{},
		sessions: map[rt.SessionKey]N.PacketConn{},
	}
	e.enterSession("user-a")
	e.enterSession("user-b")
	e.enterSession("user-c")
	e.enterSession("user-z")
	t.Cleanup(func() {
		e.leaveSession("user-z")
		e.leaveSession("user-c")
		e.leaveSession("user-b")
		e.leaveSession("user-a")
	})

	mustUpsert := func(r rt.Route) {
		t.Helper()
		if err := e.UpsertRoute(r); err != nil {
			t.Fatalf("upsert peer %d (%s): %v", r.PeerID, r.User, err)
		}
	}
	assertForwardNonLoop := func(pkt []byte, ingress, forbidden string) {
		t.Helper()
		d := e.handleIngressSession(pkt, rt.SessionKey(ingress))
		if d.Action != rt.ActionForward {
			t.Fatalf("expected %s forward, got %+v", ingress, d)
		}
		if d.EgressSession == rt.SessionKey(forbidden) {
			t.Fatalf("unexpected self-loop for %s: %+v", ingress, d)
		}
	}
	assertDrop := func(pkt []byte, ingress string) {
		t.Helper()
		if d := e.handleIngressSession(pkt, rt.SessionKey(ingress)); d.Action != rt.ActionDrop {
			t.Fatalf("expected %s drop, got %+v", ingress, d)
		}
	}

	// Route 1 owner churn: A -> B -> C. Route 2 is stable destination owner.
	mustUpsert(rt.Route{
		PeerID:          1,
		User:            "user-a",
		FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/24")},
		AllowedIPs:      []netip.Prefix{netip.MustParsePrefix("10.0.9.0/24")},
	})
	mustUpsert(rt.Route{
		PeerID:          2,
		User:            "user-z",
		FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.0.9.0/24")},
		AllowedIPs:      []netip.Prefix{netip.MustParsePrefix("10.0.9.0/24")},
	})
	mustUpsert(rt.Route{
		PeerID:          3,
		User:            "user-b",
		FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.0.1.0/24")},
		AllowedIPs:      []netip.Prefix{netip.MustParsePrefix("10.0.9.0/24")},
	})

	pktA := makeIPv4([4]byte{10, 0, 0, 77}, [4]byte{10, 0, 9, 77})
	pktB := makeIPv4([4]byte{10, 0, 1, 77}, [4]byte{10, 0, 9, 77})
	pktC := makeIPv4([4]byte{10, 0, 2, 77}, [4]byte{10, 0, 9, 77})

	assertForwardNonLoop(pktA, "user-a", "user-a")

	// A -> B: stale A must drop, B forwards without loopback.
	mustUpsert(rt.Route{
		PeerID:          1,
		User:            "user-b",
		FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.0.1.0/24")},
		AllowedIPs:      []netip.Prefix{netip.MustParsePrefix("10.0.9.0/24")},
	})
	assertDrop(pktA, "user-a")
	assertForwardNonLoop(pktB, "user-b", "user-b")

	// A -> C (direct owner switch from route perspective): stale B must drop, C forwards non-loop.
	mustUpsert(rt.Route{
		PeerID:          1,
		User:            "user-c",
		FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.0.2.0/24")},
		AllowedIPs:      []netip.Prefix{netip.MustParsePrefix("10.0.9.0/24")},
	})
	assertDrop(pktB, "user-b")
	assertForwardNonLoop(pktC, "user-c", "user-c")

	m := e.SnapshotMetrics()
	if m.ControlUpsertOK != 5 || m.ControlErrors != 0 {
		t.Fatalf("unexpected metrics in A->B->C competing-prefix chain: %+v", m)
	}
}

func TestEndpointOwnerHotUpdateSequenceAtoBAndAtoCKeepsStaleDroppedAndNonLoopForwarding(t *testing.T) {
	e := &Endpoint{
		engine:   rt.NewMemEngine(),
		peerUser: map[rt.RouteID]string{},
		userRef:  map[rt.SessionKey]int{},
		sessions: map[rt.SessionKey]N.PacketConn{},
	}
	e.enterSession("user-a")
	e.enterSession("user-b")
	e.enterSession("user-c")
	e.enterSession("user-z")
	t.Cleanup(func() {
		e.leaveSession("user-z")
		e.leaveSession("user-c")
		e.leaveSession("user-b")
		e.leaveSession("user-a")
	})

	mustUpsert := func(r rt.Route) {
		t.Helper()
		if err := e.UpsertRoute(r); err != nil {
			t.Fatalf("upsert peer %d (%s): %v", r.PeerID, r.User, err)
		}
	}
	mustDrop := func(pkt []byte, ingress string) {
		t.Helper()
		if d := e.handleIngressSession(pkt, rt.SessionKey(ingress)); d.Action != rt.ActionDrop {
			t.Fatalf("expected %s drop, got %+v", ingress, d)
		}
	}
	mustForwardNonLoop := func(pkt []byte, ingress, forbidden, want string) {
		t.Helper()
		d := e.handleIngressSession(pkt, rt.SessionKey(ingress))
		if d.Action != rt.ActionForward || d.EgressSession != rt.SessionKey(want) {
			t.Fatalf("expected %s -> %s forward, got %+v", ingress, want, d)
		}
		if d.EgressSession == rt.SessionKey(forbidden) {
			t.Fatalf("unexpected self-loop for %s: %+v", ingress, d)
		}
	}

	// Base: route 1 owned by A; route 2 is destination owner Z; route 3 is competing prefix route.
	mustUpsert(rt.Route{
		PeerID:          1,
		User:            "user-a",
		FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.2.0.0/24")},
		AllowedIPs:      []netip.Prefix{netip.MustParsePrefix("10.2.9.0/24")},
	})
	mustUpsert(rt.Route{
		PeerID:          2,
		User:            "user-z",
		FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.2.9.0/24")},
		AllowedIPs:      []netip.Prefix{netip.MustParsePrefix("10.2.9.0/24")},
	})
	mustUpsert(rt.Route{
		PeerID:          3,
		User:            "user-b",
		FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.2.1.0/24")},
		AllowedIPs:      []netip.Prefix{netip.MustParsePrefix("10.2.9.0/24")},
	})

	pktFromA := makeIPv4([4]byte{10, 2, 0, 11}, [4]byte{10, 2, 9, 11})
	pktFromB := makeIPv4([4]byte{10, 2, 1, 11}, [4]byte{10, 2, 9, 11})
	pktFromC := makeIPv4([4]byte{10, 2, 2, 11}, [4]byte{10, 2, 9, 11})

	mustForwardNonLoop(pktFromA, "user-a", "user-a", "user-z")

	// Step 1: A -> B.
	mustUpsert(rt.Route{
		PeerID:          1,
		User:            "user-b",
		FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.2.1.0/24")},
		AllowedIPs:      []netip.Prefix{netip.MustParsePrefix("10.2.9.0/24")},
	})
	mustDrop(pktFromA, "user-a")
	mustForwardNonLoop(pktFromB, "user-b", "user-b", "user-z")

	// Step 2: A -> C (следующий hot-update owner).
	mustUpsert(rt.Route{
		PeerID:          1,
		User:            "user-c",
		FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.2.2.0/24")},
		AllowedIPs:      []netip.Prefix{netip.MustParsePrefix("10.2.9.0/24")},
	})
	mustDrop(pktFromB, "user-b")
	mustForwardNonLoop(pktFromC, "user-c", "user-c", "user-z")

	m := e.SnapshotMetrics()
	if m.ControlUpsertOK != 5 || m.ControlErrors != 0 {
		t.Fatalf("unexpected metrics on A->B->C hot-update sequence: %+v", m)
	}
}

func TestEndpointOwnerSequenceWithCompetingRouteChurnPreservesAuthAndNoLoop(t *testing.T) {
	e := &Endpoint{
		engine:   rt.NewMemEngine(),
		peerUser: map[rt.RouteID]string{},
		userRef:  map[rt.SessionKey]int{},
		sessions: map[rt.SessionKey]N.PacketConn{},
	}
	e.enterSession("user-a")
	e.enterSession("user-b")
	e.enterSession("user-c")
	e.enterSession("user-z")
	t.Cleanup(func() {
		e.leaveSession("user-z")
		e.leaveSession("user-c")
		e.leaveSession("user-b")
		e.leaveSession("user-a")
	})

	mustUpsert := func(r rt.Route) {
		t.Helper()
		if err := e.UpsertRoute(r); err != nil {
			t.Fatalf("upsert peer %d (%s): %v", r.PeerID, r.User, err)
		}
	}
	mustDrop := func(pkt []byte, ingress string) {
		t.Helper()
		if d := e.handleIngressSession(pkt, rt.SessionKey(ingress)); d.Action != rt.ActionDrop {
			t.Fatalf("expected %s drop, got %+v", ingress, d)
		}
	}
	mustForward := func(pkt []byte, ingress, want string) {
		t.Helper()
		d := e.handleIngressSession(pkt, rt.SessionKey(ingress))
		if d.Action != rt.ActionForward || d.EgressSession != rt.SessionKey(want) {
			t.Fatalf("expected %s -> %s forward, got %+v", ingress, want, d)
		}
		if d.EgressSession == rt.SessionKey(ingress) {
			t.Fatalf("unexpected self-loop for %s: %+v", ingress, d)
		}
	}

	mustUpsert(rt.Route{
		PeerID:          1,
		User:            "user-a",
		FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.4.0.0/24")},
		AllowedIPs:      []netip.Prefix{netip.MustParsePrefix("10.4.9.0/24")},
	})
	mustUpsert(rt.Route{
		PeerID:          2,
		User:            "user-z",
		FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.4.9.0/24")},
		AllowedIPs:      []netip.Prefix{netip.MustParsePrefix("10.4.9.0/24")},
	})
	mustUpsert(rt.Route{
		PeerID:          3,
		User:            "user-b",
		FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.4.1.0/24")},
		AllowedIPs:      []netip.Prefix{netip.MustParsePrefix("10.4.9.0/24")},
	})

	pktA := makeIPv4([4]byte{10, 4, 0, 9}, [4]byte{10, 4, 9, 9})
	pktB := makeIPv4([4]byte{10, 4, 1, 9}, [4]byte{10, 4, 9, 9})
	pktC := makeIPv4([4]byte{10, 4, 2, 9}, [4]byte{10, 4, 9, 9})
	mustForward(pktA, "user-a", "user-z")

	// Step A->B with churn of competing route id 3.
	mustUpsert(rt.Route{
		PeerID:          1,
		User:            "user-b",
		FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.4.1.0/24")},
		AllowedIPs:      []netip.Prefix{netip.MustParsePrefix("10.4.9.0/24")},
	})
	e.RemoveRoute(3)
	mustUpsert(rt.Route{
		PeerID:          3,
		User:            "user-z",
		FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.4.8.0/24")},
		AllowedIPs:      []netip.Prefix{netip.MustParsePrefix("10.4.9.0/24")},
	})
	mustDrop(pktA, "user-a")
	mustForward(pktB, "user-b", "user-z")

	// Step B->C with route 3 churn again: stale B must be dropped, C must forward non-loop.
	mustUpsert(rt.Route{
		PeerID:          1,
		User:            "user-c",
		FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.4.2.0/24")},
		AllowedIPs:      []netip.Prefix{netip.MustParsePrefix("10.4.9.0/24")},
	})
	e.RemoveRoute(3)
	mustUpsert(rt.Route{
		PeerID:          3,
		User:            "user-z",
		FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.4.8.0/24")},
		AllowedIPs:      []netip.Prefix{netip.MustParsePrefix("10.4.9.0/24")},
	})
	mustDrop(pktB, "user-b")
	mustForward(pktC, "user-c", "user-z")

	m := e.SnapshotMetrics()
	if m.ControlUpsertOK != 7 || m.ControlRemoveOK != 2 || m.ControlErrors != 0 {
		t.Fatalf("unexpected metrics in owner sequence with route churn: %+v", m)
	}
}

func TestEndpointOwnerAtoBtoCWithCompetingRouteFlipKeepsNoLoopAndNoStaleIngress(t *testing.T) {
	e := &Endpoint{
		engine:   rt.NewMemEngine(),
		peerUser: map[rt.RouteID]string{},
		userRef:  map[rt.SessionKey]int{},
		sessions: map[rt.SessionKey]N.PacketConn{},
	}
	e.enterSession("user-a")
	e.enterSession("user-b")
	e.enterSession("user-c")
	e.enterSession("user-z")
	t.Cleanup(func() {
		e.leaveSession("user-z")
		e.leaveSession("user-c")
		e.leaveSession("user-b")
		e.leaveSession("user-a")
	})

	mustUpsert := func(r rt.Route) {
		t.Helper()
		if err := e.UpsertRoute(r); err != nil {
			t.Fatalf("upsert peer %d (%s): %v", r.PeerID, r.User, err)
		}
	}
	assertForwardNoLoop := func(pkt []byte, ingress, forbidden string) {
		t.Helper()
		d := e.handleIngressSession(pkt, rt.SessionKey(ingress))
		if d.Action != rt.ActionForward {
			t.Fatalf("expected %s forward, got %+v", ingress, d)
		}
		if d.EgressSession == rt.SessionKey(forbidden) {
			t.Fatalf("unexpected self-loop for %s: %+v", ingress, d)
		}
	}
	assertDrop := func(pkt []byte, ingress string) {
		t.Helper()
		if d := e.handleIngressSession(pkt, rt.SessionKey(ingress)); d.Action != rt.ActionDrop {
			t.Fatalf("expected %s drop, got %+v", ingress, d)
		}
	}

	// Base topology: route 1 owner churns A->B->C, route 2/3 compete for same dst prefix.
	mustUpsert(rt.Route{
		PeerID:          1,
		User:            "user-a",
		FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.6.0.0/24")},
		AllowedIPs:      []netip.Prefix{netip.MustParsePrefix("10.6.9.0/24")},
	})
	mustUpsert(rt.Route{
		PeerID:          2,
		User:            "user-z",
		FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.6.9.0/24")},
		AllowedIPs:      []netip.Prefix{netip.MustParsePrefix("10.6.9.0/24")},
	})
	mustUpsert(rt.Route{
		PeerID:          3,
		User:            "user-z",
		FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.6.8.0/24")},
		AllowedIPs:      []netip.Prefix{netip.MustParsePrefix("10.6.9.0/24")},
	})

	pktA := makeIPv4([4]byte{10, 6, 0, 13}, [4]byte{10, 6, 9, 13})
	pktB := makeIPv4([4]byte{10, 6, 1, 13}, [4]byte{10, 6, 9, 13})
	pktC := makeIPv4([4]byte{10, 6, 2, 13}, [4]byte{10, 6, 9, 13})
	assertForwardNoLoop(pktA, "user-a", "user-a")

	// A -> B, with competing route churn between updates.
	mustUpsert(rt.Route{
		PeerID:          1,
		User:            "user-b",
		FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.6.1.0/24")},
		AllowedIPs:      []netip.Prefix{netip.MustParsePrefix("10.6.9.0/24")},
	})
	e.RemoveRoute(3)
	mustUpsert(rt.Route{
		PeerID:          3,
		User:            "user-z",
		FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.6.7.0/24")},
		AllowedIPs:      []netip.Prefix{netip.MustParsePrefix("10.6.9.0/24")},
	})
	assertDrop(pktA, "user-a")
	assertForwardNoLoop(pktB, "user-b", "user-b")

	// B -> C, churn again and verify old owner B remains dropped.
	mustUpsert(rt.Route{
		PeerID:          1,
		User:            "user-c",
		FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.6.2.0/24")},
		AllowedIPs:      []netip.Prefix{netip.MustParsePrefix("10.6.9.0/24")},
	})
	e.RemoveRoute(3)
	mustUpsert(rt.Route{
		PeerID:          3,
		User:            "user-z",
		FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.6.7.0/24")},
		AllowedIPs:      []netip.Prefix{netip.MustParsePrefix("10.6.9.0/24")},
	})
	assertDrop(pktB, "user-b")
	assertForwardNoLoop(pktC, "user-c", "user-c")

	m := e.SnapshotMetrics()
	if m.ControlUpsertOK != 7 || m.ControlRemoveOK != 2 || m.ControlErrors != 0 {
		t.Fatalf("unexpected metrics in A->B->C with route flip: %+v", m)
	}
}

func TestEndpointOwnerAtoBtoCWithDestinationReAddPreservesAuthAndNoLoop(t *testing.T) {
	e := &Endpoint{
		engine:   rt.NewMemEngine(),
		peerUser: map[rt.RouteID]string{},
		userRef:  map[rt.SessionKey]int{},
		sessions: map[rt.SessionKey]N.PacketConn{},
	}
	e.enterSession("user-a")
	e.enterSession("user-b")
	e.enterSession("user-c")
	e.enterSession("user-z")
	t.Cleanup(func() {
		e.leaveSession("user-z")
		e.leaveSession("user-c")
		e.leaveSession("user-b")
		e.leaveSession("user-a")
	})

	mustUpsert := func(r rt.Route) {
		t.Helper()
		if err := e.UpsertRoute(r); err != nil {
			t.Fatalf("upsert peer %d (%s): %v", r.PeerID, r.User, err)
		}
	}
	mustDrop := func(pkt []byte, ingress string) {
		t.Helper()
		if d := e.handleIngressSession(pkt, rt.SessionKey(ingress)); d.Action != rt.ActionDrop {
			t.Fatalf("expected %s drop, got %+v", ingress, d)
		}
	}
	mustForwardNonLoop := func(pkt []byte, ingress, forbidden, want string) {
		t.Helper()
		d := e.handleIngressSession(pkt, rt.SessionKey(ingress))
		if d.Action != rt.ActionForward || d.EgressSession != rt.SessionKey(want) {
			t.Fatalf("expected %s -> %s forward, got %+v", ingress, want, d)
		}
		if d.EgressSession == rt.SessionKey(forbidden) {
			t.Fatalf("unexpected self-loop for %s: %+v", ingress, d)
		}
	}

	mustUpsert(rt.Route{
		PeerID:          1,
		User:            "user-a",
		FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.8.0.0/24")},
		AllowedIPs:      []netip.Prefix{netip.MustParsePrefix("10.8.9.0/24")},
	})
	mustUpsert(rt.Route{
		PeerID:          2,
		User:            "user-z",
		FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.8.9.0/24")},
		AllowedIPs:      []netip.Prefix{netip.MustParsePrefix("10.8.9.0/24")},
	})

	pktA := makeIPv4([4]byte{10, 8, 0, 41}, [4]byte{10, 8, 9, 41})
	pktB := makeIPv4([4]byte{10, 8, 1, 41}, [4]byte{10, 8, 9, 41})
	pktC := makeIPv4([4]byte{10, 8, 2, 41}, [4]byte{10, 8, 9, 41})
	mustForwardNonLoop(pktA, "user-a", "user-a", "user-z")

	// A -> B with destination route churn.
	mustUpsert(rt.Route{
		PeerID:          1,
		User:            "user-b",
		FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.8.1.0/24")},
		AllowedIPs:      []netip.Prefix{netip.MustParsePrefix("10.8.9.0/24")},
	})
	e.RemoveRoute(2)
	mustDrop(pktA, "user-a")
	mustDrop(pktB, "user-b") // destination route is absent.
	mustUpsert(rt.Route{
		PeerID:          2,
		User:            "user-z",
		FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.8.9.0/24")},
		AllowedIPs:      []netip.Prefix{netip.MustParsePrefix("10.8.9.0/24")},
	})
	mustForwardNonLoop(pktB, "user-b", "user-b", "user-z")

	// B -> C with destination route churn again.
	mustUpsert(rt.Route{
		PeerID:          1,
		User:            "user-c",
		FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.8.2.0/24")},
		AllowedIPs:      []netip.Prefix{netip.MustParsePrefix("10.8.9.0/24")},
	})
	e.RemoveRoute(2)
	mustDrop(pktB, "user-b")
	mustDrop(pktC, "user-c")
	mustUpsert(rt.Route{
		PeerID:          2,
		User:            "user-z",
		FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.8.9.0/24")},
		AllowedIPs:      []netip.Prefix{netip.MustParsePrefix("10.8.9.0/24")},
	})
	mustForwardNonLoop(pktC, "user-c", "user-c", "user-z")

	m := e.SnapshotMetrics()
	if m.ControlUpsertOK != 6 || m.ControlRemoveOK != 2 || m.ControlErrors != 0 {
		t.Fatalf("unexpected metrics in owner chain with destination re-add: %+v", m)
	}
}

func TestEndpointOwnerAtoBtoCIPv6CompetingPrefixNoLoopAndStaleDrop(t *testing.T) {
	e := &Endpoint{
		engine:   rt.NewMemEngine(),
		peerUser: map[rt.RouteID]string{},
		userRef:  map[rt.SessionKey]int{},
		sessions: map[rt.SessionKey]N.PacketConn{},
	}
	e.enterSession("user-a")
	e.enterSession("user-b")
	e.enterSession("user-c")
	e.enterSession("user-z")
	t.Cleanup(func() {
		e.leaveSession("user-z")
		e.leaveSession("user-c")
		e.leaveSession("user-b")
		e.leaveSession("user-a")
	})

	mustUpsert := func(r rt.Route) {
		t.Helper()
		if err := e.UpsertRoute(r); err != nil {
			t.Fatalf("upsert peer %d (%s): %v", r.PeerID, r.User, err)
		}
	}
	mustDrop := func(pkt []byte, ingress string) {
		t.Helper()
		if d := e.handleIngressSession(pkt, rt.SessionKey(ingress)); d.Action != rt.ActionDrop {
			t.Fatalf("expected %s drop, got %+v", ingress, d)
		}
	}
	mustForwardNoLoop := func(pkt []byte, ingress, forbidden, want string) {
		t.Helper()
		d := e.handleIngressSession(pkt, rt.SessionKey(ingress))
		if d.Action != rt.ActionForward || d.EgressSession != rt.SessionKey(want) {
			t.Fatalf("expected %s -> %s forward, got %+v", ingress, want, d)
		}
		if d.EgressSession == rt.SessionKey(forbidden) {
			t.Fatalf("unexpected self-loop for %s: %+v", ingress, d)
		}
	}

	mustUpsert(rt.Route{
		PeerID:          1,
		User:            "user-a",
		FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("2001:db8:20:1::/64")},
		AllowedIPs:      []netip.Prefix{netip.MustParsePrefix("2001:db8:20:9::/64")},
	})
	mustUpsert(rt.Route{
		PeerID:          2,
		User:            "user-z",
		FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("2001:db8:20:9::/64")},
		AllowedIPs:      []netip.Prefix{netip.MustParsePrefix("2001:db8:20:9::/64")},
	})
	mustUpsert(rt.Route{
		PeerID:          3,
		User:            "user-z",
		FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("2001:db8:20:8::/64")},
		AllowedIPs:      []netip.Prefix{netip.MustParsePrefix("2001:db8:20:9::/64")},
	})

	pktA := makeIPv6(netip.MustParseAddr("2001:db8:20:1::11"), netip.MustParseAddr("2001:db8:20:9::11"))
	pktB := makeIPv6(netip.MustParseAddr("2001:db8:20:2::11"), netip.MustParseAddr("2001:db8:20:9::11"))
	pktC := makeIPv6(netip.MustParseAddr("2001:db8:20:3::11"), netip.MustParseAddr("2001:db8:20:9::11"))
	mustForwardNoLoop(pktA, "user-a", "user-a", "user-z")

	mustUpsert(rt.Route{
		PeerID:          1,
		User:            "user-b",
		FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("2001:db8:20:2::/64")},
		AllowedIPs:      []netip.Prefix{netip.MustParsePrefix("2001:db8:20:9::/64")},
	})
	mustDrop(pktA, "user-a")
	mustForwardNoLoop(pktB, "user-b", "user-b", "user-z")

	mustUpsert(rt.Route{
		PeerID:          1,
		User:            "user-c",
		FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("2001:db8:20:3::/64")},
		AllowedIPs:      []netip.Prefix{netip.MustParsePrefix("2001:db8:20:9::/64")},
	})
	mustDrop(pktB, "user-b")
	mustForwardNoLoop(pktC, "user-c", "user-c", "user-z")

	m := e.SnapshotMetrics()
	if m.ControlUpsertOK != 5 || m.ControlErrors != 0 {
		t.Fatalf("unexpected metrics in IPv6 owner chain: %+v", m)
	}
}

func TestEndpointOwnerAtoBtoCAuthFailSymptomGuardWithCompetingRouteChurn(t *testing.T) {
	e := &Endpoint{
		engine:   rt.NewMemEngine(),
		peerUser: map[rt.RouteID]string{},
		userRef:  map[rt.SessionKey]int{},
		sessions: map[rt.SessionKey]N.PacketConn{},
	}
	e.enterSession("user-a")
	e.enterSession("user-b")
	e.enterSession("user-c")
	e.enterSession("user-z")
	t.Cleanup(func() {
		e.leaveSession("user-z")
		e.leaveSession("user-c")
		e.leaveSession("user-b")
		e.leaveSession("user-a")
	})

	mustUpsert := func(r rt.Route) {
		t.Helper()
		if err := e.UpsertRoute(r); err != nil {
			t.Fatalf("upsert peer %d (%s): %v", r.PeerID, r.User, err)
		}
	}
	assertForwardNoLoop := func(pkt []byte, ingress, wantEgress string) {
		t.Helper()
		d := e.handleIngressSession(pkt, rt.SessionKey(ingress))
		if d.Action != rt.ActionForward || d.EgressSession != rt.SessionKey(wantEgress) {
			t.Fatalf("expected %s -> %s forward, got %+v", ingress, wantEgress, d)
		}
		if d.EgressSession == rt.SessionKey(ingress) {
			t.Fatalf("unexpected self-loop for %s: %+v", ingress, d)
		}
	}
	assertDrop := func(pkt []byte, ingress string) {
		t.Helper()
		if d := e.handleIngressSession(pkt, rt.SessionKey(ingress)); d.Action != rt.ActionDrop {
			t.Fatalf("expected %s drop, got %+v", ingress, d)
		}
	}

	mustUpsert(rt.Route{
		PeerID:          1,
		User:            "user-a",
		FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.12.0.0/24")},
		AllowedIPs:      []netip.Prefix{netip.MustParsePrefix("10.12.9.0/24")},
	})
	mustUpsert(rt.Route{
		PeerID:          2,
		User:            "user-z",
		FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.12.9.0/24")},
		AllowedIPs:      []netip.Prefix{netip.MustParsePrefix("10.12.9.0/24")},
	})
	mustUpsert(rt.Route{
		PeerID:          3,
		User:            "user-z",
		FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.12.8.0/24")},
		AllowedIPs:      []netip.Prefix{netip.MustParsePrefix("10.12.9.0/24")},
	})

	pktA := makeIPv4([4]byte{10, 12, 0, 19}, [4]byte{10, 12, 9, 19})
	pktB := makeIPv4([4]byte{10, 12, 1, 19}, [4]byte{10, 12, 9, 19})
	pktC := makeIPv4([4]byte{10, 12, 2, 19}, [4]byte{10, 12, 9, 19})
	assertForwardNoLoop(pktA, "user-a", "user-z")

	// A->B with route churn; stale A must be dropped.
	mustUpsert(rt.Route{
		PeerID:          1,
		User:            "user-b",
		FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.12.1.0/24")},
		AllowedIPs:      []netip.Prefix{netip.MustParsePrefix("10.12.9.0/24")},
	})
	e.RemoveRoute(3)
	mustUpsert(rt.Route{
		PeerID:          3,
		User:            "user-z",
		FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.12.7.0/24")},
		AllowedIPs:      []netip.Prefix{netip.MustParsePrefix("10.12.9.0/24")},
	})
	assertDrop(pktA, "user-a")
	assertForwardNoLoop(pktB, "user-b", "user-z")

	// B->C with route churn; stale B must be dropped.
	mustUpsert(rt.Route{
		PeerID:          1,
		User:            "user-c",
		FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.12.2.0/24")},
		AllowedIPs:      []netip.Prefix{netip.MustParsePrefix("10.12.9.0/24")},
	})
	e.RemoveRoute(3)
	mustUpsert(rt.Route{
		PeerID:          3,
		User:            "user-z",
		FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.12.7.0/24")},
		AllowedIPs:      []netip.Prefix{netip.MustParsePrefix("10.12.9.0/24")},
	})
	assertDrop(pktB, "user-b")
	assertForwardNoLoop(pktC, "user-c", "user-z")

	m := e.SnapshotMetrics()
	if m.ControlUpsertOK != 7 || m.ControlRemoveOK != 2 || m.ControlErrors != 0 {
		t.Fatalf("unexpected metrics in auth-fail-symptom guard scenario: %+v", m)
	}
}

func TestEndpointOwnerAtoBtoCStepwiseDestinationWithdrawDropAndRecover(t *testing.T) {
	e := &Endpoint{
		engine:   rt.NewMemEngine(),
		peerUser: map[rt.RouteID]string{},
		userRef:  map[rt.SessionKey]int{},
		sessions: map[rt.SessionKey]N.PacketConn{},
	}
	e.enterSession("user-a")
	e.enterSession("user-b")
	e.enterSession("user-c")
	e.enterSession("user-z")
	t.Cleanup(func() {
		e.leaveSession("user-z")
		e.leaveSession("user-c")
		e.leaveSession("user-b")
		e.leaveSession("user-a")
	})

	mustUpsert := func(r rt.Route) {
		t.Helper()
		if err := e.UpsertRoute(r); err != nil {
			t.Fatalf("upsert peer %d (%s): %v", r.PeerID, r.User, err)
		}
	}
	mustDrop := func(pkt []byte, ingress string) {
		t.Helper()
		if d := e.handleIngressSession(pkt, rt.SessionKey(ingress)); d.Action != rt.ActionDrop {
			t.Fatalf("expected %s drop, got %+v", ingress, d)
		}
	}
	mustForward := func(pkt []byte, ingress, want string) {
		t.Helper()
		d := e.handleIngressSession(pkt, rt.SessionKey(ingress))
		if d.Action != rt.ActionForward || d.EgressSession != rt.SessionKey(want) {
			t.Fatalf("expected %s -> %s forward, got %+v", ingress, want, d)
		}
	}

	mustUpsert(rt.Route{
		PeerID:          1,
		User:            "user-a",
		FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.14.0.0/24")},
		AllowedIPs:      []netip.Prefix{netip.MustParsePrefix("10.14.9.0/24")},
	})
	mustUpsert(rt.Route{
		PeerID:          2,
		User:            "user-z",
		FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.14.9.0/24")},
		AllowedIPs:      []netip.Prefix{netip.MustParsePrefix("10.14.9.0/24")},
	})
	mustUpsert(rt.Route{
		PeerID:          3,
		User:            "user-z",
		FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.14.8.0/24")},
		AllowedIPs:      []netip.Prefix{netip.MustParsePrefix("10.14.9.0/24")},
	})

	steps := []struct {
		owner   string
		srcCIDR string
		srcIP   [4]byte
	}{
		{"user-a", "10.14.0.0/24", [4]byte{10, 14, 0, 18}},
		{"user-b", "10.14.1.0/24", [4]byte{10, 14, 1, 18}},
		{"user-c", "10.14.2.0/24", [4]byte{10, 14, 2, 18}},
	}
	dst := [4]byte{10, 14, 9, 18}

	for i, step := range steps {
		mustUpsert(rt.Route{
			PeerID:          1,
			User:            step.owner,
			FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix(step.srcCIDR)},
			AllowedIPs:      []netip.Prefix{netip.MustParsePrefix("10.14.9.0/24")},
		})
		// Destination withdraw window: no destination routes should force drop.
		e.RemoveRoute(2)
		e.RemoveRoute(3)
		mustDrop(makeIPv4(step.srcIP, dst), step.owner)
		mustUpsert(rt.Route{
			PeerID:          2,
			User:            "user-z",
			FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.14.9.0/24")},
			AllowedIPs:      []netip.Prefix{netip.MustParsePrefix("10.14.9.0/24")},
		})
		mustUpsert(rt.Route{
			PeerID:          3,
			User:            "user-z",
			FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.14.8.0/24")},
			AllowedIPs:      []netip.Prefix{netip.MustParsePrefix("10.14.9.0/24")},
		})
		mustForward(makeIPv4(step.srcIP, dst), step.owner, "user-z")

		if i > 0 {
			prev := steps[i-1]
			mustDrop(makeIPv4(prev.srcIP, dst), prev.owner)
		}
	}

	m := e.SnapshotMetrics()
	if m.ControlUpsertOK != 12 || m.ControlRemoveOK != 6 || m.ControlErrors != 0 {
		t.Fatalf("unexpected metrics in stepwise destination-withdraw recover chain: %+v", m)
	}
}

func TestEndpointAllowedDstOwnerChurnCompetingPrefixNoLoopAndStaleDrop(t *testing.T) {
	e := &Endpoint{
		engine:   rt.NewMemEngine(),
		peerUser: map[rt.RouteID]string{},
		userRef:  map[rt.SessionKey]int{},
		sessions: map[rt.SessionKey]N.PacketConn{},
	}
	e.enterSession("user-a")
	e.enterSession("user-b")
	e.enterSession("user-c")
	e.enterSession("user-z")
	t.Cleanup(func() {
		e.leaveSession("user-z")
		e.leaveSession("user-c")
		e.leaveSession("user-b")
		e.leaveSession("user-a")
	})

	mustUpsert := func(r rt.Route) {
		t.Helper()
		if err := e.UpsertRoute(r); err != nil {
			t.Fatalf("upsert peer %d (%s): %v", r.PeerID, r.User, err)
		}
	}
	mustDrop := func(pkt []byte, ingress string) {
		t.Helper()
		if d := e.handleIngressSession(pkt, rt.SessionKey(ingress)); d.Action != rt.ActionDrop {
			t.Fatalf("expected %s drop, got %+v", ingress, d)
		}
	}
	mustForwardNonLoop := func(pkt []byte, ingress, want string) {
		t.Helper()
		d := e.handleIngressSession(pkt, rt.SessionKey(ingress))
		if d.Action != rt.ActionForward || d.EgressSession != rt.SessionKey(want) {
			t.Fatalf("expected %s -> %s forward, got %+v", ingress, want, d)
		}
		if d.EgressSession == rt.SessionKey(ingress) {
			t.Fatalf("unexpected self-loop for %s: %+v", ingress, d)
		}
	}

	mustUpsert(rt.Route{
		PeerID:               1,
		User:                 "user-a",
		FilterSourceIPs:      []netip.Prefix{netip.MustParsePrefix("10.16.0.0/24")},
		FilterDestinationIPs: []netip.Prefix{netip.MustParsePrefix("10.16.9.0/24")},
		AllowedIPs:           []netip.Prefix{netip.MustParsePrefix("10.16.9.0/24")},
	})
	mustUpsert(rt.Route{
		PeerID:          2,
		User:            "user-z",
		FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.16.9.0/24")},
		AllowedIPs:      []netip.Prefix{netip.MustParsePrefix("10.16.9.0/24")},
	})
	mustUpsert(rt.Route{
		PeerID:          3,
		User:            "user-z",
		FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.16.8.0/24")},
		AllowedIPs:      []netip.Prefix{netip.MustParsePrefix("10.16.9.0/24")},
	})

	pktAOk := makeIPv4([4]byte{10, 16, 0, 15}, [4]byte{10, 16, 9, 15})
	pktABad := makeIPv4([4]byte{10, 16, 0, 15}, [4]byte{10, 16, 8, 15})
	pktBOk := makeIPv4([4]byte{10, 16, 1, 15}, [4]byte{10, 16, 9, 15})
	pktCOk := makeIPv4([4]byte{10, 16, 2, 15}, [4]byte{10, 16, 9, 15})
	mustDrop(pktABad, "user-a")
	mustForwardNonLoop(pktAOk, "user-a", "user-z")

	// A -> B with same-prefix competing route churn.
	mustUpsert(rt.Route{
		PeerID:               1,
		User:                 "user-b",
		FilterSourceIPs:      []netip.Prefix{netip.MustParsePrefix("10.16.1.0/24")},
		FilterDestinationIPs: []netip.Prefix{netip.MustParsePrefix("10.16.9.0/24")},
		AllowedIPs:           []netip.Prefix{netip.MustParsePrefix("10.16.9.0/24")},
	})
	e.RemoveRoute(3)
	mustUpsert(rt.Route{
		PeerID:          3,
		User:            "user-z",
		FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.16.7.0/24")},
		AllowedIPs:      []netip.Prefix{netip.MustParsePrefix("10.16.9.0/24")},
	})
	mustDrop(pktAOk, "user-a")
	mustForwardNonLoop(pktBOk, "user-b", "user-z")

	// B -> C: stale B must drop, C forwards without self-loop.
	mustUpsert(rt.Route{
		PeerID:               1,
		User:                 "user-c",
		FilterSourceIPs:      []netip.Prefix{netip.MustParsePrefix("10.16.2.0/24")},
		FilterDestinationIPs: []netip.Prefix{netip.MustParsePrefix("10.16.9.0/24")},
		AllowedIPs:           []netip.Prefix{netip.MustParsePrefix("10.16.9.0/24")},
	})
	e.RemoveRoute(3)
	mustUpsert(rt.Route{
		PeerID:          3,
		User:            "user-z",
		FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.16.7.0/24")},
		AllowedIPs:      []netip.Prefix{netip.MustParsePrefix("10.16.9.0/24")},
	})
	mustDrop(pktBOk, "user-b")
	mustForwardNonLoop(pktCOk, "user-c", "user-z")

	m := e.SnapshotMetrics()
	if m.ControlUpsertOK != 7 || m.ControlRemoveOK != 2 || m.ControlErrors != 0 {
		t.Fatalf("unexpected metrics in allowed-dst owner churn scenario: %+v", m)
	}
}

func TestEndpointOwnerChurnWithDestinationWithdrawAndCompetingLoopCandidate(t *testing.T) {
	e := &Endpoint{
		engine:   rt.NewMemEngine(),
		peerUser: map[rt.RouteID]string{},
		userRef:  map[rt.SessionKey]int{},
		sessions: map[rt.SessionKey]N.PacketConn{},
	}
	e.enterSession("user-a")
	e.enterSession("user-b")
	e.enterSession("user-c")
	e.enterSession("user-z")
	t.Cleanup(func() {
		e.leaveSession("user-z")
		e.leaveSession("user-c")
		e.leaveSession("user-b")
		e.leaveSession("user-a")
	})

	mustUpsert := func(r rt.Route) {
		t.Helper()
		if err := e.UpsertRoute(r); err != nil {
			t.Fatalf("upsert peer %d (%s): %v", r.PeerID, r.User, err)
		}
	}
	mustDrop := func(pkt []byte, ingress string) {
		t.Helper()
		if d := e.handleIngressSession(pkt, rt.SessionKey(ingress)); d.Action != rt.ActionDrop {
			t.Fatalf("expected %s drop, got %+v", ingress, d)
		}
	}
	mustForwardNonLoop := func(pkt []byte, ingress, want string) {
		t.Helper()
		d := e.handleIngressSession(pkt, rt.SessionKey(ingress))
		if d.Action != rt.ActionForward || d.EgressSession != rt.SessionKey(want) {
			t.Fatalf("expected %s -> %s forward, got %+v", ingress, want, d)
		}
		if d.EgressSession == rt.SessionKey(ingress) {
			t.Fatalf("unexpected self-loop for %s: %+v", ingress, d)
		}
	}

	mustUpsert(rt.Route{
		PeerID:               1,
		User:                 "user-a",
		FilterSourceIPs:      []netip.Prefix{netip.MustParsePrefix("10.18.0.0/24")},
		FilterDestinationIPs: []netip.Prefix{netip.MustParsePrefix("10.18.9.0/24")},
		AllowedIPs:           []netip.Prefix{netip.MustParsePrefix("10.18.9.0/24")},
	})
	mustUpsert(rt.Route{
		PeerID:          2,
		User:            "user-z",
		FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.18.9.0/24")},
		AllowedIPs:      []netip.Prefix{netip.MustParsePrefix("10.18.9.0/24")},
	})
	mustUpsert(rt.Route{
		PeerID:          3,
		User:            "user-z",
		FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.18.8.0/24")},
		AllowedIPs:      []netip.Prefix{netip.MustParsePrefix("10.18.9.0/24")},
	})

	steps := []struct {
		owner    string
		srcCIDR  string
		srcIP    [4]byte
		prevIP   [4]byte
		prevUser string
	}{
		{owner: "user-a", srcCIDR: "10.18.0.0/24", srcIP: [4]byte{10, 18, 0, 51}},
		{owner: "user-b", srcCIDR: "10.18.1.0/24", srcIP: [4]byte{10, 18, 1, 51}, prevIP: [4]byte{10, 18, 0, 51}, prevUser: "user-a"},
		{owner: "user-c", srcCIDR: "10.18.2.0/24", srcIP: [4]byte{10, 18, 2, 51}, prevIP: [4]byte{10, 18, 1, 51}, prevUser: "user-b"},
	}
	dst := [4]byte{10, 18, 9, 51}

	for i, step := range steps {
		mustUpsert(rt.Route{
			PeerID:               1,
			User:                 step.owner,
			FilterSourceIPs:      []netip.Prefix{netip.MustParsePrefix(step.srcCIDR)},
			FilterDestinationIPs: []netip.Prefix{netip.MustParsePrefix("10.18.9.0/24")},
			AllowedIPs:           []netip.Prefix{netip.MustParsePrefix("10.18.9.0/24")},
		})

		// Destination withdraw window must produce drop for current owner.
		e.RemoveRoute(2)
		e.RemoveRoute(3)
		mustDrop(makeIPv4(step.srcIP, dst), step.owner)

		// Re-add competing destination routes and ensure no self-loop after recover.
		mustUpsert(rt.Route{
			PeerID:          2,
			User:            "user-z",
			FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.18.9.0/24")},
			AllowedIPs:      []netip.Prefix{netip.MustParsePrefix("10.18.9.0/24")},
		})
		mustUpsert(rt.Route{
			PeerID:          3,
			User:            "user-z",
			FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.18.8.0/24")},
			AllowedIPs:      []netip.Prefix{netip.MustParsePrefix("10.18.9.0/24")},
		})
		mustForwardNonLoop(makeIPv4(step.srcIP, dst), step.owner, "user-z")

		if i > 0 {
			mustDrop(makeIPv4(step.prevIP, dst), step.prevUser)
		}
	}

	m := e.SnapshotMetrics()
	if m.ControlUpsertOK != 12 || m.ControlRemoveOK != 6 || m.ControlErrors != 0 {
		t.Fatalf("unexpected metrics in destination-withdraw owner churn scenario: %+v", m)
	}
}

func TestEndpointRapidOwnerFlipWithDualDestinationWithdrawPreservesNoLoopAndStaleDrop(t *testing.T) {
	e := &Endpoint{
		engine:   rt.NewMemEngine(),
		peerUser: map[rt.RouteID]string{},
		userRef:  map[rt.SessionKey]int{},
		sessions: map[rt.SessionKey]N.PacketConn{},
	}
	e.enterSession("user-a")
	e.enterSession("user-b")
	e.enterSession("user-c")
	e.enterSession("user-z")
	t.Cleanup(func() {
		e.leaveSession("user-z")
		e.leaveSession("user-c")
		e.leaveSession("user-b")
		e.leaveSession("user-a")
	})

	mustUpsert := func(r rt.Route) {
		t.Helper()
		if err := e.UpsertRoute(r); err != nil {
			t.Fatalf("upsert peer %d (%s): %v", r.PeerID, r.User, err)
		}
	}
	mustDrop := func(pkt []byte, ingress string) {
		t.Helper()
		if d := e.handleIngressSession(pkt, rt.SessionKey(ingress)); d.Action != rt.ActionDrop {
			t.Fatalf("expected %s drop, got %+v", ingress, d)
		}
	}
	mustForwardNonLoop := func(pkt []byte, ingress, want string) {
		t.Helper()
		d := e.handleIngressSession(pkt, rt.SessionKey(ingress))
		if d.Action != rt.ActionForward || d.EgressSession != rt.SessionKey(want) {
			t.Fatalf("expected %s -> %s forward, got %+v", ingress, want, d)
		}
		if d.EgressSession == rt.SessionKey(ingress) {
			t.Fatalf("unexpected self-loop for %s: %+v", ingress, d)
		}
	}

	mustUpsert(rt.Route{
		PeerID:               1,
		User:                 "user-a",
		FilterSourceIPs:      []netip.Prefix{netip.MustParsePrefix("10.20.0.0/24")},
		FilterDestinationIPs: []netip.Prefix{netip.MustParsePrefix("10.20.9.0/24")},
		AllowedIPs:           []netip.Prefix{netip.MustParsePrefix("10.20.9.0/24")},
	})
	mustUpsert(rt.Route{
		PeerID:          2,
		User:            "user-z",
		FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.20.9.0/24")},
		AllowedIPs:      []netip.Prefix{netip.MustParsePrefix("10.20.9.0/24")},
	})
	mustUpsert(rt.Route{
		PeerID:          3,
		User:            "user-z",
		FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.20.8.0/24")},
		AllowedIPs:      []netip.Prefix{netip.MustParsePrefix("10.20.9.0/24")},
	})

	steps := []struct {
		owner   string
		srcCIDR string
		srcIP   [4]byte
	}{
		{"user-a", "10.20.0.0/24", [4]byte{10, 20, 0, 31}},
		{"user-b", "10.20.1.0/24", [4]byte{10, 20, 1, 31}},
		{"user-c", "10.20.2.0/24", [4]byte{10, 20, 2, 31}},
		{"user-a", "10.20.3.0/24", [4]byte{10, 20, 3, 31}},
	}
	dst := [4]byte{10, 20, 9, 31}

	for i, step := range steps {
		mustUpsert(rt.Route{
			PeerID:               1,
			User:                 step.owner,
			FilterSourceIPs:      []netip.Prefix{netip.MustParsePrefix(step.srcCIDR)},
			FilterDestinationIPs: []netip.Prefix{netip.MustParsePrefix("10.20.9.0/24")},
			AllowedIPs:           []netip.Prefix{netip.MustParsePrefix("10.20.9.0/24")},
		})

		// During full destination withdraw, dataplane must drop instead of looping.
		e.RemoveRoute(2)
		e.RemoveRoute(3)
		mustDrop(makeIPv4(step.srcIP, dst), step.owner)

		mustUpsert(rt.Route{
			PeerID:          2,
			User:            "user-z",
			FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.20.9.0/24")},
			AllowedIPs:      []netip.Prefix{netip.MustParsePrefix("10.20.9.0/24")},
		})
		mustUpsert(rt.Route{
			PeerID:          3,
			User:            "user-z",
			FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.20.8.0/24")},
			AllowedIPs:      []netip.Prefix{netip.MustParsePrefix("10.20.9.0/24")},
		})
		mustForwardNonLoop(makeIPv4(step.srcIP, dst), step.owner, "user-z")

		if i > 0 {
			prev := steps[i-1]
			mustDrop(makeIPv4(prev.srcIP, dst), prev.owner)
		}
	}
}

func TestEndpointAllowedDstOwnerFlipWithCompetingReAddPreservesNoLoopAndStaleDrop(t *testing.T) {
	e := &Endpoint{
		engine:   rt.NewMemEngine(),
		peerUser: map[rt.RouteID]string{},
		userRef:  map[rt.SessionKey]int{},
		sessions: map[rt.SessionKey]N.PacketConn{},
	}
	e.enterSession("user-a")
	e.enterSession("user-b")
	e.enterSession("user-c")
	e.enterSession("user-z")
	t.Cleanup(func() {
		e.leaveSession("user-z")
		e.leaveSession("user-c")
		e.leaveSession("user-b")
		e.leaveSession("user-a")
	})

	mustUpsert := func(r rt.Route) {
		t.Helper()
		if err := e.UpsertRoute(r); err != nil {
			t.Fatalf("upsert peer %d (%s): %v", r.PeerID, r.User, err)
		}
	}
	mustDrop := func(pkt []byte, ingress string) {
		t.Helper()
		if d := e.handleIngressSession(pkt, rt.SessionKey(ingress)); d.Action != rt.ActionDrop {
			t.Fatalf("expected %s drop, got %+v", ingress, d)
		}
	}
	mustForward := func(pkt []byte, ingress, want string) {
		t.Helper()
		d := e.handleIngressSession(pkt, rt.SessionKey(ingress))
		if d.Action != rt.ActionForward || d.EgressSession != rt.SessionKey(want) {
			t.Fatalf("expected %s -> %s forward, got %+v", ingress, want, d)
		}
		if d.EgressSession == rt.SessionKey(ingress) {
			t.Fatalf("unexpected self-loop for %s: %+v", ingress, d)
		}
	}

	mustUpsert(rt.Route{
		PeerID:               41,
		User:                 "user-a",
		FilterSourceIPs:      []netip.Prefix{netip.MustParsePrefix("10.22.0.0/24")},
		FilterDestinationIPs: []netip.Prefix{netip.MustParsePrefix("10.22.9.0/24")},
		AllowedIPs:           []netip.Prefix{netip.MustParsePrefix("10.22.9.0/24")},
	})
	mustUpsert(rt.Route{
		PeerID:          42,
		User:            "user-z",
		FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.22.9.0/24")},
		AllowedIPs:      []netip.Prefix{netip.MustParsePrefix("10.22.9.0/24")},
	})
	mustUpsert(rt.Route{
		PeerID:          43,
		User:            "user-z",
		FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.22.8.0/24")},
		AllowedIPs:      []netip.Prefix{netip.MustParsePrefix("10.22.9.0/24")},
	})

	stages := []struct {
		owner    string
		srcCIDR  string
		srcIP    [4]byte
		prevUser string
		prevIP   [4]byte
	}{
		{owner: "user-a", srcCIDR: "10.22.0.0/24", srcIP: [4]byte{10, 22, 0, 13}},
		{owner: "user-b", srcCIDR: "10.22.1.0/24", srcIP: [4]byte{10, 22, 1, 13}, prevUser: "user-a", prevIP: [4]byte{10, 22, 0, 13}},
		{owner: "user-c", srcCIDR: "10.22.2.0/24", srcIP: [4]byte{10, 22, 2, 13}, prevUser: "user-b", prevIP: [4]byte{10, 22, 1, 13}},
	}
	dstAllowed := [4]byte{10, 22, 9, 66}
	dstDenied := [4]byte{10, 22, 8, 66}
	for i, stage := range stages {
		mustUpsert(rt.Route{
			PeerID:               41,
			User:                 stage.owner,
			FilterSourceIPs:      []netip.Prefix{netip.MustParsePrefix(stage.srcCIDR)},
			FilterDestinationIPs: []netip.Prefix{netip.MustParsePrefix("10.22.9.0/24")},
			AllowedIPs:           []netip.Prefix{netip.MustParsePrefix("10.22.9.0/24")},
		})

		mustDrop(makeIPv4(stage.srcIP, dstDenied), stage.owner)

		e.RemoveRoute(42)
		e.RemoveRoute(43)
		mustUpsert(rt.Route{
			PeerID:          42,
			User:            "user-z",
			FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.22.9.0/24")},
			AllowedIPs:      []netip.Prefix{netip.MustParsePrefix("10.22.9.0/24")},
		})
		mustUpsert(rt.Route{
			PeerID:          43,
			User:            "user-z",
			FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.22.8.0/24")},
			AllowedIPs:      []netip.Prefix{netip.MustParsePrefix("10.22.9.0/24")},
		})
		mustForward(makeIPv4(stage.srcIP, dstAllowed), stage.owner, "user-z")

		if i > 0 {
			mustDrop(makeIPv4(stage.prevIP, dstAllowed), stage.prevUser)
		}
	}

	m := e.SnapshotMetrics()
	if m.ControlUpsertOK != 12 || m.ControlRemoveOK != 6 || m.ControlErrors != 0 {
		t.Fatalf("unexpected metrics in allowed-dst owner flip scenario: %+v", m)
	}
}

func TestEndpointRuntimeUpsertRemoveCycleMaintainsNoLoopAndMetrics(t *testing.T) {
	e := &Endpoint{
		engine:   rt.NewMemEngine(),
		peerUser: map[rt.RouteID]string{},
		userRef:  map[rt.SessionKey]int{},
		sessions: map[rt.SessionKey]N.PacketConn{},
	}
	e.enterSession("user-a")
	e.enterSession("user-b")
	e.enterSession("user-c")
	e.enterSession("user-z")
	t.Cleanup(func() {
		e.leaveSession("user-z")
		e.leaveSession("user-c")
		e.leaveSession("user-b")
		e.leaveSession("user-a")
	})

	mustUpsert := func(r rt.Route) {
		t.Helper()
		if err := e.UpsertRoute(r); err != nil {
			t.Fatalf("upsert peer %d (%s): %v", r.PeerID, r.User, err)
		}
	}
	mustDrop := func(pkt []byte, ingress string) {
		t.Helper()
		if d := e.handleIngressSession(pkt, rt.SessionKey(ingress)); d.Action != rt.ActionDrop {
			t.Fatalf("expected %s drop, got %+v", ingress, d)
		}
	}
	mustForward := func(pkt []byte, ingress, want string) {
		t.Helper()
		d := e.handleIngressSession(pkt, rt.SessionKey(ingress))
		if d.Action != rt.ActionForward || d.EgressSession != rt.SessionKey(want) {
			t.Fatalf("expected %s -> %s forward, got %+v", ingress, want, d)
		}
		if d.EgressSession == rt.SessionKey(ingress) {
			t.Fatalf("unexpected self-loop for %s: %+v", ingress, d)
		}
	}

	// Route 100 (owner route) will be hot-updated A->B->C with remove/re-add of destination route.
	mustUpsert(rt.Route{
		PeerID:               100,
		User:                 "user-a",
		FilterSourceIPs:      []netip.Prefix{netip.MustParsePrefix("10.24.0.0/24")},
		FilterDestinationIPs: []netip.Prefix{netip.MustParsePrefix("10.24.9.0/24")},
		AllowedIPs:           []netip.Prefix{netip.MustParsePrefix("10.24.9.0/24")},
	})
	mustUpsert(rt.Route{
		PeerID:          101,
		User:            "user-z",
		FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.24.9.0/24")},
		AllowedIPs:      []netip.Prefix{netip.MustParsePrefix("10.24.9.0/24")},
	})

	steps := []struct {
		owner   string
		srcCIDR string
		srcIP   [4]byte
		prev    string
		prevIP  [4]byte
	}{
		{owner: "user-a", srcCIDR: "10.24.0.0/24", srcIP: [4]byte{10, 24, 0, 17}},
		{owner: "user-b", srcCIDR: "10.24.1.0/24", srcIP: [4]byte{10, 24, 1, 17}, prev: "user-a", prevIP: [4]byte{10, 24, 0, 17}},
		{owner: "user-c", srcCIDR: "10.24.2.0/24", srcIP: [4]byte{10, 24, 2, 17}, prev: "user-b", prevIP: [4]byte{10, 24, 1, 17}},
	}
	dst := [4]byte{10, 24, 9, 17}

	for i, step := range steps {
		mustUpsert(rt.Route{
			PeerID:               100,
			User:                 step.owner,
			FilterSourceIPs:      []netip.Prefix{netip.MustParsePrefix(step.srcCIDR)},
			FilterDestinationIPs: []netip.Prefix{netip.MustParsePrefix("10.24.9.0/24")},
			AllowedIPs:           []netip.Prefix{netip.MustParsePrefix("10.24.9.0/24")},
		})
		e.RemoveRoute(101)
		mustDrop(makeIPv4(step.srcIP, dst), step.owner)
		mustUpsert(rt.Route{
			PeerID:          101,
			User:            "user-z",
			FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.24.9.0/24")},
			AllowedIPs:      []netip.Prefix{netip.MustParsePrefix("10.24.9.0/24")},
		})
		mustForward(makeIPv4(step.srcIP, dst), step.owner, "user-z")
		if i > 0 {
			mustDrop(makeIPv4(step.prevIP, dst), step.prev)
		}
	}

	m := e.SnapshotMetrics()
	if m.ControlUpsertOK != 8 || m.ControlRemoveOK != 3 || m.ControlErrors != 0 {
		t.Fatalf("unexpected metrics in runtime upsert/remove cycle: %+v", m)
	}
}

func TestEndpointOwnerRotationWithDestinationOscillationPreservesNoLoop(t *testing.T) {
	e := &Endpoint{
		engine:   rt.NewMemEngine(),
		peerUser: map[rt.RouteID]string{},
		userRef:  map[rt.SessionKey]int{},
		sessions: map[rt.SessionKey]N.PacketConn{},
	}
	e.enterSession("user-a")
	e.enterSession("user-b")
	e.enterSession("user-c")
	e.enterSession("user-z")
	t.Cleanup(func() {
		e.leaveSession("user-z")
		e.leaveSession("user-c")
		e.leaveSession("user-b")
		e.leaveSession("user-a")
	})

	mustUpsert := func(r rt.Route) {
		t.Helper()
		if err := e.UpsertRoute(r); err != nil {
			t.Fatalf("upsert peer %d (%s): %v", r.PeerID, r.User, err)
		}
	}
	mustDrop := func(pkt []byte, ingress string) {
		t.Helper()
		if d := e.handleIngressSession(pkt, rt.SessionKey(ingress)); d.Action != rt.ActionDrop {
			t.Fatalf("expected %s drop, got %+v", ingress, d)
		}
	}
	mustForward := func(pkt []byte, ingress, want string) {
		t.Helper()
		d := e.handleIngressSession(pkt, rt.SessionKey(ingress))
		if d.Action != rt.ActionForward || d.EgressSession != rt.SessionKey(want) {
			t.Fatalf("expected %s -> %s forward, got %+v", ingress, want, d)
		}
		if d.EgressSession == rt.SessionKey(ingress) {
			t.Fatalf("unexpected self-loop for %s: %+v", ingress, d)
		}
	}

	mustUpsert(rt.Route{
		PeerID:               110,
		User:                 "user-a",
		FilterSourceIPs:      []netip.Prefix{netip.MustParsePrefix("10.26.0.0/24")},
		FilterDestinationIPs: []netip.Prefix{netip.MustParsePrefix("10.26.9.0/24")},
		AllowedIPs:           []netip.Prefix{netip.MustParsePrefix("10.26.9.0/24")},
	})
	mustUpsert(rt.Route{PeerID: 111, User: "user-z", FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.26.9.0/24")}, AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.26.9.0/24")}})
	mustUpsert(rt.Route{PeerID: 112, User: "user-z", FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.26.8.0/24")}, AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.26.9.0/24")}})

	steps := []struct {
		owner   string
		srcCIDR string
		srcIP   [4]byte
	}{
		{owner: "user-a", srcCIDR: "10.26.0.0/24", srcIP: [4]byte{10, 26, 0, 19}},
		{owner: "user-b", srcCIDR: "10.26.1.0/24", srcIP: [4]byte{10, 26, 1, 19}},
		{owner: "user-c", srcCIDR: "10.26.2.0/24", srcIP: [4]byte{10, 26, 2, 19}},
	}
	dst := [4]byte{10, 26, 9, 19}

	for _, step := range steps {
		mustUpsert(rt.Route{
			PeerID:               110,
			User:                 step.owner,
			FilterSourceIPs:      []netip.Prefix{netip.MustParsePrefix(step.srcCIDR)},
			FilterDestinationIPs: []netip.Prefix{netip.MustParsePrefix("10.26.9.0/24")},
			AllowedIPs:           []netip.Prefix{netip.MustParsePrefix("10.26.9.0/24")},
		})

		e.RemoveRoute(111)
		e.RemoveRoute(112)
		mustDrop(makeIPv4(step.srcIP, dst), step.owner)
		mustUpsert(rt.Route{PeerID: 111, User: "user-z", FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.26.9.0/24")}, AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.26.9.0/24")}})
		mustUpsert(rt.Route{PeerID: 112, User: "user-z", FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.26.8.0/24")}, AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.26.9.0/24")}})
		mustForward(makeIPv4(step.srcIP, dst), step.owner, "user-z")
	}

	m := e.SnapshotMetrics()
	if m.ControlUpsertOK != 12 || m.ControlRemoveOK != 6 || m.ControlErrors != 0 {
		t.Fatalf("unexpected metrics in owner rotation + destination oscillation scenario: %+v", m)
	}
}

func TestEndpointOwnerRotationWithAllowedDstGuardAndCompetingLoopRoute(t *testing.T) {
	e := &Endpoint{
		engine:   rt.NewMemEngine(),
		peerUser: map[rt.RouteID]string{},
		userRef:  map[rt.SessionKey]int{},
		sessions: map[rt.SessionKey]N.PacketConn{},
	}
	for _, sk := range []rt.SessionKey{"client-a", "client-b", "client-c", "server-z"} {
		e.enterSession(sk)
	}
	t.Cleanup(func() {
		for _, sk := range []rt.SessionKey{"server-z", "client-c", "client-b", "client-a"} {
			e.leaveSession(sk)
		}
	})
	mustUpsert := func(r rt.Route) {
		t.Helper()
		if err := e.UpsertRoute(r); err != nil {
			t.Fatalf("upsert peer %d (%s): %v", r.PeerID, r.User, err)
		}
	}
	mustDrop := func(pkt []byte, ingress string) {
		t.Helper()
		if d := e.handleIngressSession(pkt, rt.SessionKey(ingress)); d.Action != rt.ActionDrop {
			t.Fatalf("expected %s drop, got %+v", ingress, d)
		}
	}
	mustForward := func(pkt []byte, ingress, want string) {
		t.Helper()
		d := e.handleIngressSession(pkt, rt.SessionKey(ingress))
		if d.Action != rt.ActionForward || d.EgressSession != rt.SessionKey(want) {
			t.Fatalf("expected %s -> %s forward, got %+v", ingress, want, d)
		}
		if d.EgressSession == rt.SessionKey(ingress) {
			t.Fatalf("unexpected self-loop for %s: %+v", ingress, d)
		}
	}

	mustUpsert(rt.Route{
		PeerID:               130,
		User:                 "client-a",
		FilterSourceIPs:      []netip.Prefix{netip.MustParsePrefix("10.44.0.0/24")},
		FilterDestinationIPs: []netip.Prefix{netip.MustParsePrefix("10.44.9.0/24")},
		AllowedIPs:           []netip.Prefix{netip.MustParsePrefix("10.44.0.0/24")},
	})
	mustUpsert(rt.Route{
		PeerID:          131,
		User:            "server-z",
		FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.44.9.0/24")},
		AllowedIPs:      []netip.Prefix{netip.MustParsePrefix("10.44.9.0/24")},
	})
	mustUpsert(rt.Route{
		PeerID:          132,
		User:            "server-z",
		FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.44.8.0/24")},
		AllowedIPs:      []netip.Prefix{netip.MustParsePrefix("10.44.9.0/24")},
	})

	steps := []struct {
		owner   string
		srcCIDR string
		srcIP   [4]byte
	}{
		{owner: "client-a", srcCIDR: "10.44.0.0/24", srcIP: [4]byte{10, 44, 0, 7}},
		{owner: "client-b", srcCIDR: "10.44.1.0/24", srcIP: [4]byte{10, 44, 1, 7}},
		{owner: "client-c", srcCIDR: "10.44.2.0/24", srcIP: [4]byte{10, 44, 2, 7}},
	}
	dstGood := [4]byte{10, 44, 9, 7}
	dstBad := [4]byte{10, 44, 8, 7}
	var prevOwner string
	var prevIP [4]byte
	for i, step := range steps {
		mustUpsert(rt.Route{
			PeerID:               130,
			User:                 step.owner,
			FilterSourceIPs:      []netip.Prefix{netip.MustParsePrefix(step.srcCIDR)},
			FilterDestinationIPs: []netip.Prefix{netip.MustParsePrefix("10.44.9.0/24")},
			AllowedIPs:           []netip.Prefix{netip.MustParsePrefix(step.srcCIDR)},
		})

		mustForward(makeIPv4(step.srcIP, dstGood), step.owner, "server-z")
		mustDrop(makeIPv4(step.srcIP, dstBad), step.owner)
		if i > 0 {
			mustDrop(makeIPv4(prevIP, dstGood), prevOwner)
		}
		prevOwner = step.owner
		prevIP = step.srcIP
	}

	m := e.SnapshotMetrics()
	if m.ControlUpsertOK != 6 || m.ControlErrors != 0 {
		t.Fatalf("unexpected metrics after owner rotation with AllowedDst guard: %+v", m)
	}
}

func TestEndpointControlPlaneStepOwnerSequenceMaintainsNoLoopAndMetrics(t *testing.T) {
	e := &Endpoint{
		engine:   rt.NewMemEngine(),
		peerUser: map[rt.RouteID]string{},
		userRef:  map[rt.SessionKey]int{},
		sessions: map[rt.SessionKey]N.PacketConn{},
	}
	for _, sk := range []rt.SessionKey{"client1", "client2", "client3", "dst-z"} {
		e.enterSession(sk)
	}
	t.Cleanup(func() {
		for _, sk := range []rt.SessionKey{"dst-z", "client3", "client2", "client1"} {
			e.leaveSession(sk)
		}
	})
	mustUpsert := func(r rt.Route) {
		t.Helper()
		if err := e.UpsertRoute(r); err != nil {
			t.Fatalf("upsert peer %d (%s): %v", r.PeerID, r.User, err)
		}
	}
	mustDrop := func(pkt []byte, ingress string) {
		t.Helper()
		if d := e.handleIngressSession(pkt, rt.SessionKey(ingress)); d.Action != rt.ActionDrop {
			t.Fatalf("expected %s drop, got %+v", ingress, d)
		}
	}
	mustForwardNoLoop := func(pkt []byte, ingress, want string) {
		t.Helper()
		d := e.handleIngressSession(pkt, rt.SessionKey(ingress))
		if d.Action != rt.ActionForward || d.EgressSession != rt.SessionKey(want) {
			t.Fatalf("expected %s -> %s forward, got %+v", ingress, want, d)
		}
		if d.EgressSession == rt.SessionKey(ingress) {
			t.Fatalf("unexpected self-loop for %s: %+v", ingress, d)
		}
	}

	mustUpsert(rt.Route{
		PeerID:               150,
		User:                 "client1",
		FilterSourceIPs:      []netip.Prefix{netip.MustParsePrefix("10.31.0.2/32")},
		FilterDestinationIPs: []netip.Prefix{netip.MustParsePrefix("10.31.9.0/24")},
		AllowedIPs:           []netip.Prefix{netip.MustParsePrefix("10.31.0.2/32")},
	})
	mustUpsert(rt.Route{
		PeerID:          151,
		User:            "dst-z",
		FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.31.9.0/24")},
		AllowedIPs:      []netip.Prefix{netip.MustParsePrefix("10.31.9.0/24")},
	})
	mustUpsert(rt.Route{
		PeerID:          152,
		User:            "dst-z",
		FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.31.8.0/24")},
		AllowedIPs:      []netip.Prefix{netip.MustParsePrefix("10.31.9.0/24")},
	})

	steps := []struct {
		owner    string
		srcCIDR  string
		srcIP    [4]byte
		prevIP   [4]byte
		prevUser string
	}{
		{owner: "client1", srcCIDR: "10.31.0.2/32", srcIP: [4]byte{10, 31, 0, 2}},
		{owner: "client2", srcCIDR: "10.31.0.3/32", srcIP: [4]byte{10, 31, 0, 3}, prevIP: [4]byte{10, 31, 0, 2}, prevUser: "client1"},
		{owner: "client3", srcCIDR: "10.31.0.4/32", srcIP: [4]byte{10, 31, 0, 4}, prevIP: [4]byte{10, 31, 0, 3}, prevUser: "client2"},
	}
	dst := [4]byte{10, 31, 9, 44}

	for i, step := range steps {
		mustUpsert(rt.Route{
			PeerID:               150,
			User:                 step.owner,
			FilterSourceIPs:      []netip.Prefix{netip.MustParsePrefix(step.srcCIDR)},
			FilterDestinationIPs: []netip.Prefix{netip.MustParsePrefix("10.31.9.0/24")},
			AllowedIPs:           []netip.Prefix{netip.MustParsePrefix(step.srcCIDR)},
		})
		e.RemoveRoute(152)
		mustUpsert(rt.Route{
			PeerID:          152,
			User:            "dst-z",
			FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.31.8.0/24")},
			AllowedIPs:      []netip.Prefix{netip.MustParsePrefix("10.31.9.0/24")},
		})
		mustForwardNoLoop(makeIPv4(step.srcIP, dst), step.owner, "dst-z")
		if i > 0 {
			mustDrop(makeIPv4(step.prevIP, dst), step.prevUser)
		}
	}

	m := e.SnapshotMetrics()
	if m.ControlUpsertOK != 9 || m.ControlRemoveOK != 3 || m.ControlErrors != 0 {
		t.Fatalf("unexpected metrics in control-plane owner A->B->C sequence: %+v", m)
	}
}

func TestEndpointOwnerRotationWithLoopOnlyWindowTracksDropAndForwardMetrics(t *testing.T) {
	e := &Endpoint{
		engine:   rt.NewMemEngine(),
		peerUser: map[rt.RouteID]string{},
		userRef:  map[rt.SessionKey]int{},
		sessions: map[rt.SessionKey]N.PacketConn{},
	}
	for _, sk := range []rt.SessionKey{"client-a", "client-b", "client-c", "dst-z"} {
		e.enterSession(sk)
	}
	t.Cleanup(func() {
		for _, sk := range []rt.SessionKey{"dst-z", "client-c", "client-b", "client-a"} {
			e.leaveSession(sk)
		}
	})
	mustUpsert := func(r rt.Route) {
		t.Helper()
		if err := e.UpsertRoute(r); err != nil {
			t.Fatalf("upsert peer %d (%s): %v", r.PeerID, r.User, err)
		}
	}
	mustForward := func(pkt []byte, ingress, want string) {
		t.Helper()
		d := e.handleIngressSession(pkt, rt.SessionKey(ingress))
		if d.Action != rt.ActionForward || d.EgressSession != rt.SessionKey(want) {
			t.Fatalf("expected %s -> %s forward, got %+v", ingress, want, d)
		}
		if d.EgressSession == rt.SessionKey(ingress) {
			t.Fatalf("unexpected self-loop for %s: %+v", ingress, d)
		}
		e.forwardPackets.Add(1)
	}
	mustDrop := func(pkt []byte, ingress string) {
		t.Helper()
		if d := e.handleIngressSession(pkt, rt.SessionKey(ingress)); d.Action != rt.ActionDrop {
			t.Fatalf("expected %s drop, got %+v", ingress, d)
		}
		e.dropPackets.Add(1)
	}

	mustUpsert(rt.Route{PeerID: 160, User: "client-a", FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.61.0.2/32")}, FilterDestinationIPs: []netip.Prefix{netip.MustParsePrefix("10.61.9.0/24")}, AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.61.0.2/32")}})
	mustUpsert(rt.Route{PeerID: 161, User: "dst-z", FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.61.9.0/24")}, AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.61.9.0/24")}})
	mustUpsert(rt.Route{PeerID: 162, User: "dst-z", FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.61.8.0/24")}, AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.61.9.0/24")}})

	steps := []struct {
		owner   string
		srcCIDR string
		srcIP   [4]byte
	}{
		{owner: "client-a", srcCIDR: "10.61.0.2/32", srcIP: [4]byte{10, 61, 0, 2}},
		{owner: "client-b", srcCIDR: "10.61.0.3/32", srcIP: [4]byte{10, 61, 0, 3}},
		{owner: "client-c", srcCIDR: "10.61.0.4/32", srcIP: [4]byte{10, 61, 0, 4}},
	}
	dst := [4]byte{10, 61, 9, 60}
	for _, step := range steps {
		mustUpsert(rt.Route{PeerID: 160, User: step.owner, FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix(step.srcCIDR)}, FilterDestinationIPs: []netip.Prefix{netip.MustParsePrefix("10.61.9.0/24")}, AllowedIPs: []netip.Prefix{netip.MustParsePrefix(step.srcCIDR)}})
		mustForward(makeIPv4(step.srcIP, dst), step.owner, "dst-z")
		e.RemoveRoute(161)
		e.RemoveRoute(162)
		mustDrop(makeIPv4(step.srcIP, dst), step.owner)
		mustUpsert(rt.Route{PeerID: 161, User: "dst-z", FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.61.9.0/24")}, AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.61.9.0/24")}})
		mustUpsert(rt.Route{PeerID: 162, User: "dst-z", FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.61.8.0/24")}, AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.61.9.0/24")}})
		mustForward(makeIPv4(step.srcIP, dst), step.owner, "dst-z")
	}
	m := e.SnapshotMetrics()
	if m.ForwardPackets != 6 || m.DropPackets != 3 || m.ControlUpsertOK != 12 || m.ControlRemoveOK != 6 || m.ControlErrors != 0 {
		t.Fatalf("unexpected metrics in loop-only window sequence: %+v", m)
	}
}

func TestEndpointOwnerAtoBtoCWithLoopCandidateAndOfflineDestinationRecoversWithoutSelfLoop(t *testing.T) {
	e := &Endpoint{
		engine:   rt.NewMemEngine(),
		peerUser: map[rt.RouteID]string{},
		userRef:  map[rt.SessionKey]int{},
		sessions: map[rt.SessionKey]N.PacketConn{},
	}
	for _, sk := range []rt.SessionKey{"owner-a", "owner-b", "owner-c", "dst-z"} {
		e.enterSession(sk)
	}
	t.Cleanup(func() {
		for _, sk := range []rt.SessionKey{"dst-z", "owner-c", "owner-b", "owner-a"} {
			e.leaveSession(sk)
		}
	})

	mustUpsert := func(r rt.Route) {
		t.Helper()
		if err := e.UpsertRoute(r); err != nil {
			t.Fatalf("upsert peer %d (%s): %v", r.PeerID, r.User, err)
		}
	}
	mustDrop := func(pkt []byte, ingress rt.SessionKey) {
		t.Helper()
		if d := e.handleIngressSession(pkt, ingress); d.Action != rt.ActionDrop {
			t.Fatalf("expected %s drop, got %+v", ingress, d)
		}
	}
	mustForwardNoLoop := func(pkt []byte, ingress, want rt.SessionKey) {
		t.Helper()
		d := e.handleIngressSession(pkt, ingress)
		if d.Action != rt.ActionForward || d.EgressSession != want {
			t.Fatalf("expected %s -> %s forward, got %+v", ingress, want, d)
		}
		if d.EgressSession == ingress {
			t.Fatalf("unexpected self-loop for %s: %+v", ingress, d)
		}
	}

	mustUpsert(rt.Route{
		PeerID:               170,
		User:                 "owner-a",
		FilterSourceIPs:      []netip.Prefix{netip.MustParsePrefix("10.63.0.0/24")},
		FilterDestinationIPs: []netip.Prefix{netip.MustParsePrefix("10.63.9.0/24")},
		AllowedIPs:           []netip.Prefix{netip.MustParsePrefix("10.63.0.0/24")},
	})
	mustUpsert(rt.Route{
		PeerID:          171,
		User:            "dst-z",
		FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.63.9.0/24")},
		AllowedIPs:      []netip.Prefix{netip.MustParsePrefix("10.63.9.0/24")},
	})
	mustUpsert(rt.Route{
		PeerID:          172,
		User:            "dst-z",
		FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.63.8.0/24")},
		AllowedIPs:      []netip.Prefix{netip.MustParsePrefix("10.63.9.0/24")},
	})

	steps := []struct {
		owner   rt.SessionKey
		srcCIDR string
		srcIP   [4]byte
	}{
		{owner: "owner-a", srcCIDR: "10.63.0.0/24", srcIP: [4]byte{10, 63, 0, 5}},
		{owner: "owner-b", srcCIDR: "10.63.1.0/24", srcIP: [4]byte{10, 63, 1, 5}},
		{owner: "owner-c", srcCIDR: "10.63.2.0/24", srcIP: [4]byte{10, 63, 2, 5}},
	}
	dst := [4]byte{10, 63, 9, 5}
	for i, step := range steps {
		mustUpsert(rt.Route{
			PeerID:               170,
			User:                 string(step.owner),
			FilterSourceIPs:      []netip.Prefix{netip.MustParsePrefix(step.srcCIDR)},
			FilterDestinationIPs: []netip.Prefix{netip.MustParsePrefix("10.63.9.0/24")},
			AllowedIPs:           []netip.Prefix{netip.MustParsePrefix(step.srcCIDR)},
		})

		// Simulate loop-only/offline destination window.
		e.RemoveRoute(171)
		e.RemoveRoute(172)
		mustDrop(makeIPv4(step.srcIP, dst), step.owner)

		mustUpsert(rt.Route{
			PeerID:          171,
			User:            "dst-z",
			FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.63.9.0/24")},
			AllowedIPs:      []netip.Prefix{netip.MustParsePrefix("10.63.9.0/24")},
		})
		mustUpsert(rt.Route{
			PeerID:          172,
			User:            "dst-z",
			FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.63.8.0/24")},
			AllowedIPs:      []netip.Prefix{netip.MustParsePrefix("10.63.9.0/24")},
		})
		mustForwardNoLoop(makeIPv4(step.srcIP, dst), step.owner, "dst-z")

		if i > 0 {
			prev := steps[i-1]
			mustDrop(makeIPv4(prev.srcIP, dst), prev.owner)
		}
	}

	m := e.SnapshotMetrics()
	if m.ControlUpsertOK != 12 || m.ControlRemoveOK != 6 || m.ControlErrors != 0 {
		t.Fatalf("unexpected metrics in owner A->B->C with offline destination recovery: %+v", m)
	}
}

func TestEndpointOwnerAtoBtoCWithCompetingSMBPrefixLoopWindowTracksControlMetrics(t *testing.T) {
	e := &Endpoint{
		engine:   rt.NewMemEngine(),
		peerUser: map[rt.RouteID]string{},
		userRef:  map[rt.SessionKey]int{},
		sessions: map[rt.SessionKey]N.PacketConn{},
	}
	for _, sk := range []rt.SessionKey{"owner-a", "owner-b", "owner-c", "dst-smb"} {
		e.enterSession(sk)
	}
	t.Cleanup(func() {
		for _, sk := range []rt.SessionKey{"dst-smb", "owner-c", "owner-b", "owner-a"} {
			e.leaveSession(sk)
		}
	})

	mustUpsert := func(r rt.Route) {
		t.Helper()
		if err := e.UpsertRoute(r); err != nil {
			t.Fatalf("upsert peer %d (%s): %v", r.PeerID, r.User, err)
		}
	}
	mustDrop := func(pkt []byte, ingress rt.SessionKey) {
		t.Helper()
		if d := e.handleIngressSession(pkt, ingress); d.Action != rt.ActionDrop {
			t.Fatalf("expected %s drop, got %+v", ingress, d)
		}
	}
	mustForwardNoLoop := func(pkt []byte, ingress, want rt.SessionKey) {
		t.Helper()
		d := e.handleIngressSession(pkt, ingress)
		if d.Action != rt.ActionForward || d.EgressSession != want {
			t.Fatalf("expected %s -> %s forward, got %+v", ingress, want, d)
		}
		if d.EgressSession == ingress {
			t.Fatalf("unexpected self-loop for %s: %+v", ingress, d)
		}
	}

	mustUpsert(rt.Route{
		PeerID:               180,
		User:                 "owner-a",
		FilterSourceIPs:      []netip.Prefix{netip.MustParsePrefix("10.71.0.0/24")},
		FilterDestinationIPs: []netip.Prefix{netip.MustParsePrefix("10.71.9.0/24")},
		AllowedIPs:           []netip.Prefix{netip.MustParsePrefix("10.71.0.0/24")},
	})
	mustUpsert(rt.Route{
		PeerID:          181,
		User:            "dst-smb",
		FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.71.9.0/24")},
		AllowedIPs:      []netip.Prefix{netip.MustParsePrefix("10.71.9.0/24")},
	})
	steps := []struct {
		owner   rt.SessionKey
		srcCIDR string
		srcIP   [4]byte
	}{
		{owner: "owner-a", srcCIDR: "10.71.0.0/24", srcIP: [4]byte{10, 71, 0, 10}},
		{owner: "owner-b", srcCIDR: "10.71.1.0/24", srcIP: [4]byte{10, 71, 1, 10}},
		{owner: "owner-c", srcCIDR: "10.71.2.0/24", srcIP: [4]byte{10, 71, 2, 10}},
	}
	dst := [4]byte{10, 71, 9, 10}
	for i, step := range steps {
		mustUpsert(rt.Route{
			PeerID:               180,
			User:                 string(step.owner),
			FilterSourceIPs:      []netip.Prefix{netip.MustParsePrefix(step.srcCIDR)},
			FilterDestinationIPs: []netip.Prefix{netip.MustParsePrefix("10.71.9.0/24")},
			AllowedIPs:           []netip.Prefix{netip.MustParsePrefix(step.srcCIDR)},
		})
		mustUpsert(rt.Route{
			PeerID:          182,
			User:            string(step.owner),
			FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix(step.srcCIDR)},
			AllowedIPs:      []netip.Prefix{netip.MustParsePrefix("10.71.9.10/32")},
		})

		// Keep competing /32 destination route; then withdraw /24 to emulate loop-only hole.
		e.RemoveRoute(181)
		mustDrop(makeIPv4(step.srcIP, dst), step.owner)

		mustUpsert(rt.Route{
			PeerID:          181,
			User:            "dst-smb",
			FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.71.9.0/24")},
			AllowedIPs:      []netip.Prefix{netip.MustParsePrefix("10.71.9.0/24")},
		})
		mustForwardNoLoop(makeIPv4(step.srcIP, dst), step.owner, "dst-smb")

		if i > 0 {
			prev := steps[i-1]
			mustDrop(makeIPv4(prev.srcIP, dst), prev.owner)
		}
	}

	m := e.SnapshotMetrics()
	if m.ControlUpsertOK != 11 || m.ControlRemoveOK != 3 || m.ControlErrors != 0 {
		t.Fatalf("unexpected metrics for SMB-prefix loop window flow: %+v", m)
	}
}

func TestEndpointAllowedDstSMB32OwnerChurnLoopWindowTracksMetrics(t *testing.T) {
	e := &Endpoint{
		engine:   rt.NewMemEngine(),
		peerUser: map[rt.RouteID]string{},
		userRef:  map[rt.SessionKey]int{},
		sessions: map[rt.SessionKey]N.PacketConn{},
	}
	for _, sk := range []rt.SessionKey{"owner-a", "owner-b", "owner-c", "dst-smb"} {
		e.enterSession(sk)
	}
	t.Cleanup(func() {
		for _, sk := range []rt.SessionKey{"dst-smb", "owner-c", "owner-b", "owner-a"} {
			e.leaveSession(sk)
		}
	})

	mustUpsert := func(r rt.Route) {
		t.Helper()
		if err := e.UpsertRoute(r); err != nil {
			t.Fatalf("upsert peer %d (%s): %v", r.PeerID, r.User, err)
		}
	}
	mustDrop := func(pkt []byte, ingress rt.SessionKey) {
		t.Helper()
		if d := e.handleIngressSession(pkt, ingress); d.Action != rt.ActionDrop {
			t.Fatalf("expected %s drop, got %+v", ingress, d)
		}
	}
	mustForwardNoLoop := func(pkt []byte, ingress, want rt.SessionKey) {
		t.Helper()
		d := e.handleIngressSession(pkt, ingress)
		if d.Action != rt.ActionForward || d.EgressSession != want {
			t.Fatalf("expected %s -> %s forward, got %+v", ingress, want, d)
		}
		if d.EgressSession == ingress {
			t.Fatalf("unexpected self-loop for %s: %+v", ingress, d)
		}
	}

	mustUpsert(rt.Route{
		PeerID:               190,
		User:                 "owner-a",
		FilterSourceIPs:      []netip.Prefix{netip.MustParsePrefix("10.90.0.0/24")},
		FilterDestinationIPs: []netip.Prefix{netip.MustParsePrefix("10.90.9.10/32")},
		AllowedIPs:           []netip.Prefix{netip.MustParsePrefix("10.90.0.0/24")},
	})
	mustUpsert(rt.Route{
		PeerID:          191,
		User:            "dst-smb",
		FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.90.9.0/24")},
		AllowedIPs:      []netip.Prefix{netip.MustParsePrefix("10.90.9.0/24")},
	})
	steps := []struct {
		owner   rt.SessionKey
		srcCIDR string
		srcIP   [4]byte
	}{
		{owner: "owner-a", srcCIDR: "10.90.0.0/24", srcIP: [4]byte{10, 90, 0, 10}},
		{owner: "owner-b", srcCIDR: "10.90.1.0/24", srcIP: [4]byte{10, 90, 1, 10}},
		{owner: "owner-c", srcCIDR: "10.90.2.0/24", srcIP: [4]byte{10, 90, 2, 10}},
	}
	dst := [4]byte{10, 90, 9, 10}
	for i, step := range steps {
		mustUpsert(rt.Route{
			PeerID:               190,
			User:                 string(step.owner),
			FilterSourceIPs:      []netip.Prefix{netip.MustParsePrefix(step.srcCIDR)},
			FilterDestinationIPs: []netip.Prefix{netip.MustParsePrefix("10.90.9.10/32")},
			AllowedIPs:           []netip.Prefix{netip.MustParsePrefix(step.srcCIDR)},
		})
		mustUpsert(rt.Route{
			PeerID:          192,
			User:            string(step.owner),
			FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix(step.srcCIDR)},
			AllowedIPs:      []netip.Prefix{netip.MustParsePrefix("10.90.9.10/32")},
		})

		// /32 loop route stays, /24 removed: must drop (no self-loop fallback).
		e.RemoveRoute(191)
		mustDrop(makeIPv4(step.srcIP, dst), step.owner)

		mustUpsert(rt.Route{
			PeerID:          191,
			User:            "dst-smb",
			FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.90.9.0/24")},
			AllowedIPs:      []netip.Prefix{netip.MustParsePrefix("10.90.9.0/24")},
		})
		mustForwardNoLoop(makeIPv4(step.srcIP, dst), step.owner, "dst-smb")

		if i > 0 {
			prev := steps[i-1]
			mustDrop(makeIPv4(prev.srcIP, dst), prev.owner)
		}
	}

	m := e.SnapshotMetrics()
	if m.ControlUpsertOK != 11 || m.ControlRemoveOK != 3 || m.ControlErrors != 0 {
		t.Fatalf("unexpected metrics for AllowedDst /32 SMB owner churn loop window: %+v", m)
	}
}

func TestEndpointBiDirectionalSMBAuthSymptomLoopWindowPreservesNoLoopAndMetrics(t *testing.T) {
	e := &Endpoint{
		engine:   rt.NewMemEngine(),
		peerUser: map[rt.RouteID]string{},
		userRef:  map[rt.SessionKey]int{},
		sessions: map[rt.SessionKey]N.PacketConn{},
	}
	for _, sk := range []rt.SessionKey{"owner-a", "owner-c", "dst-z"} {
		e.enterSession(sk)
	}
	t.Cleanup(func() {
		for _, sk := range []rt.SessionKey{"dst-z", "owner-c", "owner-a"} {
			e.leaveSession(sk)
		}
	})

	mustUpsert := func(r rt.Route) {
		t.Helper()
		if err := e.UpsertRoute(r); err != nil {
			t.Fatalf("upsert peer %d (%s): %v", r.PeerID, r.User, err)
		}
	}
	mustForwardNoLoop := func(pkt []byte, ingress rt.SessionKey) {
		t.Helper()
		d := e.handleIngressSession(pkt, ingress)
		if d.Action != rt.ActionForward {
			t.Fatalf("expected %s forward, got %+v", ingress, d)
		}
		if d.EgressSession == ingress {
			t.Fatalf("unexpected self-loop for %s: %+v", ingress, d)
		}
	}

	mustUpsert(rt.Route{
		PeerID:               401,
		User:                 "owner-a",
		FilterSourceIPs:      []netip.Prefix{netip.MustParsePrefix("10.92.0.0/24")},
		FilterDestinationIPs: []netip.Prefix{netip.MustParsePrefix("10.92.9.0/24")},
		AllowedIPs:           []netip.Prefix{netip.MustParsePrefix("10.92.0.0/24")},
	})
	mustUpsert(rt.Route{
		PeerID:               402,
		User:                 "owner-c",
		FilterSourceIPs:      []netip.Prefix{netip.MustParsePrefix("10.92.2.0/24")},
		FilterDestinationIPs: []netip.Prefix{netip.MustParsePrefix("10.92.9.0/24")},
		AllowedIPs:           []netip.Prefix{netip.MustParsePrefix("10.92.2.0/24")},
	})
	mustUpsert(rt.Route{
		PeerID:          403,
		User:            "dst-z",
		FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.92.9.0/24")},
		AllowedIPs:      []netip.Prefix{netip.MustParsePrefix("10.92.9.0/24")},
	})
	mustUpsert(rt.Route{
		PeerID:          404,
		User:            "owner-a",
		FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.92.0.0/24")},
		AllowedIPs:      []netip.Prefix{netip.MustParsePrefix("10.92.9.10/32")},
	})
	mustUpsert(rt.Route{
		PeerID:          405,
		User:            "owner-c",
		FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.92.2.0/24")},
		AllowedIPs:      []netip.Prefix{netip.MustParsePrefix("10.92.9.11/32")},
	})

	pktAtoC := makeIPv4([4]byte{10, 92, 0, 10}, [4]byte{10, 92, 9, 11})
	pktCtoA := makeIPv4([4]byte{10, 92, 2, 10}, [4]byte{10, 92, 9, 10})
	for i := 0; i < 4; i++ {
		mustForwardNoLoop(pktAtoC, "owner-a")
		mustForwardNoLoop(pktCtoA, "owner-c")

		// Withdraw /24 destination route: forwarding may fall back to opposite /32 owner,
		// but it must never self-loop.
		e.RemoveRoute(403)
		mustForwardNoLoop(pktAtoC, "owner-a")
		mustForwardNoLoop(pktCtoA, "owner-c")

		// Recover destination route and ensure both directions recover without loop.
		mustUpsert(rt.Route{
			PeerID:          403,
			User:            "dst-z",
			FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.92.9.0/24")},
			AllowedIPs:      []netip.Prefix{netip.MustParsePrefix("10.92.9.0/24")},
		})
		mustForwardNoLoop(pktAtoC, "owner-a")
		mustForwardNoLoop(pktCtoA, "owner-c")
	}

	m := e.SnapshotMetrics()
	if m.ControlUpsertOK != 9 || m.ControlRemoveOK != 4 || m.ControlErrors != 0 {
		t.Fatalf("unexpected metrics for bi-directional SMB auth-symptom guard: %+v", m)
	}
}

func TestEndpointSMB32OwnerFlipWithFallbackChurnTracksMetricsAndNoLoop(t *testing.T) {
	e := &Endpoint{
		engine:   rt.NewMemEngine(),
		peerUser: map[rt.RouteID]string{},
		userRef:  map[rt.SessionKey]int{},
		sessions: map[rt.SessionKey]N.PacketConn{},
	}
	for _, sk := range []rt.SessionKey{"owner-a", "owner-b", "owner-c", "dst-smb"} {
		e.enterSession(sk)
	}
	t.Cleanup(func() {
		for _, sk := range []rt.SessionKey{"dst-smb", "owner-c", "owner-b", "owner-a"} {
			e.leaveSession(sk)
		}
	})

	mustUpsert := func(r rt.Route) {
		t.Helper()
		if err := e.UpsertRoute(r); err != nil {
			t.Fatalf("upsert peer %d (%s): %v", r.PeerID, r.User, err)
		}
	}
	mustDrop := func(pkt []byte, ingress rt.SessionKey) {
		t.Helper()
		if d := e.handleIngressSession(pkt, ingress); d.Action != rt.ActionDrop {
			t.Fatalf("expected %s drop, got %+v", ingress, d)
		}
	}
	mustForwardNoLoop := func(pkt []byte, ingress, want rt.SessionKey) {
		t.Helper()
		d := e.handleIngressSession(pkt, ingress)
		if d.Action != rt.ActionForward || d.EgressSession != want {
			t.Fatalf("expected %s -> %s forward, got %+v", ingress, want, d)
		}
		if d.EgressSession == ingress {
			t.Fatalf("unexpected self-loop for %s: %+v", ingress, d)
		}
	}

	mustUpsert(rt.Route{
		PeerID:               510,
		User:                 "owner-a",
		FilterSourceIPs:      []netip.Prefix{netip.MustParsePrefix("10.96.0.0/24")},
		FilterDestinationIPs: []netip.Prefix{netip.MustParsePrefix("10.96.9.10/32")},
		AllowedIPs:           []netip.Prefix{netip.MustParsePrefix("10.96.0.0/24")},
	})
	mustUpsert(rt.Route{
		PeerID:          511,
		User:            "dst-smb",
		FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.96.9.0/24")},
		AllowedIPs:      []netip.Prefix{netip.MustParsePrefix("10.96.9.0/24")},
	})
	mustUpsert(rt.Route{
		PeerID:          512,
		User:            "owner-a",
		FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.96.0.0/24")},
		AllowedIPs:      []netip.Prefix{netip.MustParsePrefix("10.96.9.10/32")},
	})

	steps := []struct {
		owner   rt.SessionKey
		srcCIDR string
		srcIP   [4]byte
	}{
		{owner: "owner-a", srcCIDR: "10.96.0.0/24", srcIP: [4]byte{10, 96, 0, 10}},
		{owner: "owner-b", srcCIDR: "10.96.1.0/24", srcIP: [4]byte{10, 96, 1, 10}},
		{owner: "owner-c", srcCIDR: "10.96.2.0/24", srcIP: [4]byte{10, 96, 2, 10}},
	}
	dst := [4]byte{10, 96, 9, 10}
	for i, step := range steps {
		mustUpsert(rt.Route{
			PeerID:               510,
			User:                 string(step.owner),
			FilterSourceIPs:      []netip.Prefix{netip.MustParsePrefix(step.srcCIDR)},
			FilterDestinationIPs: []netip.Prefix{netip.MustParsePrefix("10.96.9.10/32")},
			AllowedIPs:           []netip.Prefix{netip.MustParsePrefix(step.srcCIDR)},
		})
		mustUpsert(rt.Route{
			PeerID:          512,
			User:            string(step.owner),
			FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix(step.srcCIDR)},
			AllowedIPs:      []netip.Prefix{netip.MustParsePrefix("10.96.9.10/32")},
		})

		// /32 loop-candidate exists, /24 route should carry forwarding.
		mustForwardNoLoop(makeIPv4(step.srcIP, dst), step.owner, "dst-smb")

		// Withdraw /24 destination route => only loop candidate remains => drop.
		e.RemoveRoute(511)
		mustDrop(makeIPv4(step.srcIP, dst), step.owner)

		// Re-add /24 destination route and ensure deterministic non-loop recovery.
		mustUpsert(rt.Route{
			PeerID:          511,
			User:            "dst-smb",
			FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.96.9.0/24")},
			AllowedIPs:      []netip.Prefix{netip.MustParsePrefix("10.96.9.0/24")},
		})
		mustForwardNoLoop(makeIPv4(step.srcIP, dst), step.owner, "dst-smb")

		if i > 0 {
			prev := steps[i-1]
			mustDrop(makeIPv4(prev.srcIP, dst), prev.owner)
		}
	}

	m := e.SnapshotMetrics()
	if m.ControlUpsertOK != 12 || m.ControlRemoveOK != 3 || m.ControlErrors != 0 {
		t.Fatalf("unexpected metrics for SMB /32 owner-flip fallback churn: %+v", m)
	}
}

func TestEndpointBidirectionalSMB32OwnerRotationWithTieChurnNoLoopAndMetrics(t *testing.T) {
	e := &Endpoint{
		engine:   rt.NewMemEngine(),
		peerUser: map[rt.RouteID]string{},
		userRef:  map[rt.SessionKey]int{},
		sessions: map[rt.SessionKey]N.PacketConn{},
	}
	for _, sk := range []rt.SessionKey{"owner-a", "owner-c", "dst-x", "dst-y"} {
		e.enterSession(sk)
	}
	t.Cleanup(func() {
		for _, sk := range []rt.SessionKey{"dst-y", "dst-x", "owner-c", "owner-a"} {
			e.leaveSession(sk)
		}
	})

	mustUpsert := func(r rt.Route) {
		t.Helper()
		if err := e.UpsertRoute(r); err != nil {
			t.Fatalf("upsert peer %d (%s): %v", r.PeerID, r.User, err)
		}
	}
	mustForwardNoLoop := func(pkt []byte, ingress rt.SessionKey) {
		t.Helper()
		d := e.handleIngressSession(pkt, ingress)
		if d.Action != rt.ActionForward {
			t.Fatalf("expected forward for %s, got %+v", ingress, d)
		}
		if d.EgressSession == ingress {
			t.Fatalf("unexpected self-loop for %s: %+v", ingress, d)
		}
	}

	mustUpsert(rt.Route{
		PeerID:               520,
		User:                 "owner-a",
		FilterSourceIPs:      []netip.Prefix{netip.MustParsePrefix("10.98.0.0/24")},
		FilterDestinationIPs: []netip.Prefix{netip.MustParsePrefix("10.98.9.0/24")},
		AllowedIPs:           []netip.Prefix{netip.MustParsePrefix("10.98.0.0/24")},
	})
	mustUpsert(rt.Route{
		PeerID:               521,
		User:                 "owner-c",
		FilterSourceIPs:      []netip.Prefix{netip.MustParsePrefix("10.98.2.0/24")},
		FilterDestinationIPs: []netip.Prefix{netip.MustParsePrefix("10.98.9.0/24")},
		AllowedIPs:           []netip.Prefix{netip.MustParsePrefix("10.98.2.0/24")},
	})
	mustUpsert(rt.Route{PeerID: 522, User: "owner-a", FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.98.0.0/24")}, AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.98.9.10/32")}})
	mustUpsert(rt.Route{PeerID: 523, User: "owner-c", FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.98.2.0/24")}, AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.98.9.11/32")}})
	mustUpsert(rt.Route{PeerID: 524, User: "dst-x", FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.98.9.0/24")}, AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.98.9.0/24")}})
	mustUpsert(rt.Route{PeerID: 525, User: "dst-y", FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.98.8.0/24")}, AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.98.9.0/24")}})

	pktAtoC := makeIPv4([4]byte{10, 98, 0, 10}, [4]byte{10, 98, 9, 11})
	pktCtoA := makeIPv4([4]byte{10, 98, 2, 10}, [4]byte{10, 98, 9, 10})
	for i := 0; i < 6; i++ {
		// Churn equal-prefix destination routes and owner /32 routes.
		e.RemoveRoute(524)
		e.RemoveRoute(525)
		mustUpsert(rt.Route{PeerID: 524, User: "dst-x", FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.98.9.0/24")}, AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.98.9.0/24")}})
		mustUpsert(rt.Route{PeerID: 525, User: "dst-y", FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.98.8.0/24")}, AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.98.9.0/24")}})

		if i%2 == 0 {
			mustUpsert(rt.Route{PeerID: 522, User: "owner-a", FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.98.0.0/24")}, AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.98.9.10/32")}})
			mustUpsert(rt.Route{PeerID: 523, User: "owner-c", FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.98.2.0/24")}, AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.98.9.11/32")}})
		} else {
			mustUpsert(rt.Route{PeerID: 522, User: "owner-a", FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.98.0.0/24")}, AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.98.9.11/32")}})
			mustUpsert(rt.Route{PeerID: 523, User: "owner-c", FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.98.2.0/24")}, AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.98.9.10/32")}})
		}
		mustForwardNoLoop(pktAtoC, "owner-a")
		mustForwardNoLoop(pktCtoA, "owner-c")
	}

	m := e.SnapshotMetrics()
	if m.ControlUpsertOK != 30 || m.ControlRemoveOK != 12 || m.ControlErrors != 0 {
		t.Fatalf("unexpected metrics in bidirectional SMB /32 tie churn: %+v", m)
	}
}

func TestEndpointBidirectionalSMBLoopOnlyWindowDropRecoveryTracksMetrics(t *testing.T) {
	e := &Endpoint{
		engine:   rt.NewMemEngine(),
		peerUser: map[rt.RouteID]string{},
		userRef:  map[rt.SessionKey]int{},
		sessions: map[rt.SessionKey]N.PacketConn{},
	}
	for _, sk := range []rt.SessionKey{"owner-a", "owner-c", "dst-smb"} {
		e.enterSession(sk)
	}
	t.Cleanup(func() {
		for _, sk := range []rt.SessionKey{"dst-smb", "owner-c", "owner-a"} {
			e.leaveSession(sk)
		}
	})

	mustUpsert := func(r rt.Route) {
		t.Helper()
		if err := e.UpsertRoute(r); err != nil {
			t.Fatalf("upsert peer %d (%s): %v", r.PeerID, r.User, err)
		}
	}
	mustForwardNoLoop := func(pkt []byte, ingress rt.SessionKey) {
		t.Helper()
		d := e.handleIngressSession(pkt, ingress)
		if d.Action != rt.ActionForward {
			t.Fatalf("expected %s forward in non-loop window, got %+v", ingress, d)
		}
		if d.EgressSession == ingress {
			t.Fatalf("unexpected self-loop for %s: %+v", ingress, d)
		}
	}
	mustNoSelfLoopInLoopOnlyWindow := func(pkt []byte, ingress rt.SessionKey) {
		t.Helper()
		if d := e.handleIngressSession(pkt, ingress); d.EgressSession == ingress {
			t.Fatalf("expected %s to avoid self-egress in loop-only window, got %+v", ingress, d)
		}
	}

	mustUpsert(rt.Route{
		PeerID:               530,
		User:                 "owner-a",
		FilterSourceIPs:      []netip.Prefix{netip.MustParsePrefix("10.99.10.0/24")},
		FilterDestinationIPs: []netip.Prefix{netip.MustParsePrefix("10.99.19.0/24")},
		AllowedIPs:           []netip.Prefix{netip.MustParsePrefix("10.99.10.0/24")},
	})
	mustUpsert(rt.Route{
		PeerID:               531,
		User:                 "owner-c",
		FilterSourceIPs:      []netip.Prefix{netip.MustParsePrefix("10.99.12.0/24")},
		FilterDestinationIPs: []netip.Prefix{netip.MustParsePrefix("10.99.19.0/24")},
		AllowedIPs:           []netip.Prefix{netip.MustParsePrefix("10.99.12.0/24")},
	})
	mustUpsert(rt.Route{
		PeerID:          532,
		User:            "owner-a",
		FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.99.10.0/24")},
		AllowedIPs:      []netip.Prefix{netip.MustParsePrefix("10.99.19.10/32")},
	})
	mustUpsert(rt.Route{
		PeerID:          533,
		User:            "owner-c",
		FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.99.12.0/24")},
		AllowedIPs:      []netip.Prefix{netip.MustParsePrefix("10.99.19.11/32")},
	})
	mustUpsert(rt.Route{
		PeerID:          534,
		User:            "dst-smb",
		FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.99.19.0/24")},
		AllowedIPs:      []netip.Prefix{netip.MustParsePrefix("10.99.19.0/24")},
	})

	pktAtoC := makeIPv4([4]byte{10, 99, 10, 10}, [4]byte{10, 99, 19, 11})
	pktCtoA := makeIPv4([4]byte{10, 99, 12, 10}, [4]byte{10, 99, 19, 10})
	for i := 0; i < 4; i++ {
		mustUpsert(rt.Route{
			PeerID:          532,
			User:            "owner-a",
			FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.99.10.0/24")},
			AllowedIPs:      []netip.Prefix{netip.MustParsePrefix("10.99.19.10/32")},
		})
		mustUpsert(rt.Route{
			PeerID:          533,
			User:            "owner-c",
			FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.99.12.0/24")},
			AllowedIPs:      []netip.Prefix{netip.MustParsePrefix("10.99.19.11/32")},
		})
		mustForwardNoLoop(pktAtoC, "owner-a")
		mustForwardNoLoop(pktCtoA, "owner-c")

		e.RemoveRoute(534)
		mustNoSelfLoopInLoopOnlyWindow(pktAtoC, "owner-a")
		mustNoSelfLoopInLoopOnlyWindow(pktCtoA, "owner-c")

		mustUpsert(rt.Route{
			PeerID:          534,
			User:            "dst-smb",
			FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.99.19.0/24")},
			AllowedIPs:      []netip.Prefix{netip.MustParsePrefix("10.99.19.0/24")},
		})
		mustForwardNoLoop(pktAtoC, "owner-a")
		mustForwardNoLoop(pktCtoA, "owner-c")
	}

	m := e.SnapshotMetrics()
	if m.ControlUpsertOK != 17 || m.ControlRemoveOK != 4 || m.ControlErrors != 0 {
		t.Fatalf("unexpected metrics in bidirectional loop-only SMB recovery: %+v", m)
	}
}

func TestEndpointSMBAuthSymptomGuardWithOwnerFlipCompetingRouteNoLoop(t *testing.T) {
	e := &Endpoint{
		engine:   rt.NewMemEngine(),
		peerUser: map[rt.RouteID]string{},
		userRef:  map[rt.SessionKey]int{},
		sessions: map[rt.SessionKey]N.PacketConn{},
	}
	for _, sk := range []rt.SessionKey{"owner-a", "owner-b", "owner-c", "dst-smb", "dst-fallback"} {
		e.enterSession(sk)
	}
	t.Cleanup(func() {
		for _, sk := range []rt.SessionKey{"dst-fallback", "dst-smb", "owner-c", "owner-b", "owner-a"} {
			e.leaveSession(sk)
		}
	})

	mustUpsert := func(r rt.Route) {
		t.Helper()
		if err := e.UpsertRoute(r); err != nil {
			t.Fatalf("upsert peer %d (%s): %v", r.PeerID, r.User, err)
		}
	}
	mustForwardNoLoop := func(pkt []byte, ingress rt.SessionKey) {
		t.Helper()
		d := e.handleIngressSession(pkt, ingress)
		if d.Action != rt.ActionForward {
			t.Fatalf("expected forward for %s, got %+v", ingress, d)
		}
		if d.EgressSession == ingress {
			t.Fatalf("unexpected self-loop for %s: %+v", ingress, d)
		}
	}
	mustDrop := func(pkt []byte, ingress rt.SessionKey) {
		t.Helper()
		if d := e.handleIngressSession(pkt, ingress); d.Action != rt.ActionDrop {
			t.Fatalf("expected drop for stale ingress %s, got %+v", ingress, d)
		}
	}

	mustUpsert(rt.Route{PeerID: 540, User: "owner-a", FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.101.0.0/24")}, FilterDestinationIPs: []netip.Prefix{netip.MustParsePrefix("10.101.9.0/24")}, AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.101.0.0/24")}})
	mustUpsert(rt.Route{PeerID: 541, User: "owner-b", FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.101.1.0/24")}, FilterDestinationIPs: []netip.Prefix{netip.MustParsePrefix("10.101.9.0/24")}, AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.101.1.0/24")}})
	mustUpsert(rt.Route{PeerID: 542, User: "owner-c", FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.101.2.0/24")}, FilterDestinationIPs: []netip.Prefix{netip.MustParsePrefix("10.101.9.0/24")}, AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.101.2.0/24")}})
	mustUpsert(rt.Route{PeerID: 543, User: "owner-a", FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.101.0.0/24")}, AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.101.9.10/32")}})
	mustUpsert(rt.Route{PeerID: 544, User: "owner-c", FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.101.2.0/24")}, AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.101.9.11/32")}})
	mustUpsert(rt.Route{PeerID: 545, User: "dst-smb", FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.101.9.0/24")}, AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.101.9.0/24")}})
	mustUpsert(rt.Route{PeerID: 546, User: "dst-fallback", FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.101.8.0/24")}, AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.101.9.0/24")}})

	type step struct {
		owner rt.SessionKey
		srcIP [4]byte
		stale rt.SessionKey
	}
	steps := []step{
		{owner: "owner-a", srcIP: [4]byte{10, 101, 0, 10}},
		{owner: "owner-b", srcIP: [4]byte{10, 101, 1, 10}, stale: "owner-a"},
		{owner: "owner-c", srcIP: [4]byte{10, 101, 2, 10}, stale: "owner-b"},
	}
	dst := [4]byte{10, 101, 9, 11}
	for i, s := range steps {
		mustUpsert(rt.Route{
			PeerID:          543,
			User:            string(s.owner),
			FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix(netip.AddrFrom4(s.srcIP).String() + "/32")},
			AllowedIPs:      []netip.Prefix{netip.MustParsePrefix("10.101.9.10/32")},
		})
		if i%2 == 0 {
			mustUpsert(rt.Route{PeerID: 545, User: "dst-smb", FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.101.9.0/24")}, AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.101.9.0/24")}})
			mustUpsert(rt.Route{PeerID: 546, User: "dst-fallback", FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.101.8.0/24")}, AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.101.9.0/24")}})
		} else {
			e.RemoveRoute(545)
			mustUpsert(rt.Route{PeerID: 545, User: "dst-smb", FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.101.9.0/24")}, AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.101.9.0/24")}})
		}

		mustForwardNoLoop(makeIPv4(s.srcIP, dst), s.owner)
		if s.stale != "" {
			mustDrop(makeIPv4(steps[i-1].srcIP, dst), s.stale)
		}
	}

	m := e.SnapshotMetrics()
	if m.ControlUpsertOK != 15 || m.ControlRemoveOK != 1 || m.ControlErrors != 0 {
		t.Fatalf("unexpected metrics in smb auth symptom owner-flip guard: %+v", m)
	}
}

func TestEndpointBidirectionalSMBLoopGuardWithRouteIDTieChurnTracksMetrics(t *testing.T) {
	e := &Endpoint{
		engine:   rt.NewMemEngine(),
		peerUser: map[rt.RouteID]string{},
		userRef:  map[rt.SessionKey]int{},
		sessions: map[rt.SessionKey]N.PacketConn{},
	}
	for _, sk := range []rt.SessionKey{"owner-a", "owner-c", "dst-smb", "dst-fallback"} {
		e.enterSession(sk)
	}
	t.Cleanup(func() {
		for _, sk := range []rt.SessionKey{"dst-fallback", "dst-smb", "owner-c", "owner-a"} {
			e.leaveSession(sk)
		}
	})
	mustUpsert := func(r rt.Route) {
		t.Helper()
		if err := e.UpsertRoute(r); err != nil {
			t.Fatalf("upsert peer %d (%s): %v", r.PeerID, r.User, err)
		}
	}
	mustForwardNoLoop := func(pkt []byte, ingress rt.SessionKey) {
		t.Helper()
		d := e.handleIngressSession(pkt, ingress)
		if d.Action != rt.ActionForward {
			t.Fatalf("expected forward for %s, got %+v", ingress, d)
		}
		if d.EgressSession == ingress {
			t.Fatalf("unexpected self-loop for %s: %+v", ingress, d)
		}
	}
	mustNoSelfLoopInLoopOnlyWindow := func(pkt []byte, ingress rt.SessionKey) {
		t.Helper()
		d := e.handleIngressSession(pkt, ingress)
		if d.EgressSession == ingress {
			t.Fatalf("loop-only window produced self-egress for %s: %+v", ingress, d)
		}
		if d.Action != rt.ActionDrop && d.Action != rt.ActionForward {
			t.Fatalf("loop-only window must be forward/drop for %s, got %+v", ingress, d)
		}
	}

	mustUpsert(rt.Route{PeerID: 560, User: "owner-a", FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.121.0.0/24")}, FilterDestinationIPs: []netip.Prefix{netip.MustParsePrefix("10.121.9.0/24")}, AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.121.0.0/24")}})
	mustUpsert(rt.Route{PeerID: 561, User: "owner-c", FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.121.2.0/24")}, FilterDestinationIPs: []netip.Prefix{netip.MustParsePrefix("10.121.9.0/24")}, AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.121.2.0/24")}})
	mustUpsert(rt.Route{PeerID: 562, User: "owner-a", FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.121.0.0/24")}, AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.121.9.10/32")}})
	mustUpsert(rt.Route{PeerID: 563, User: "owner-c", FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.121.2.0/24")}, AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.121.9.11/32")}})
	mustUpsert(rt.Route{PeerID: 564, User: "dst-smb", FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.121.9.0/24")}, AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.121.9.0/24")}})
	mustUpsert(rt.Route{PeerID: 565, User: "dst-fallback", FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.121.8.0/24")}, AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.121.9.0/24")}})

	pktAtoC := makeIPv4([4]byte{10, 121, 0, 10}, [4]byte{10, 121, 9, 11})
	pktCtoA := makeIPv4([4]byte{10, 121, 2, 10}, [4]byte{10, 121, 9, 10})
	for i := 0; i < 4; i++ {
		mustUpsert(rt.Route{PeerID: 564, User: "dst-smb", FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.121.9.0/24")}, AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.121.9.0/24")}})
		mustUpsert(rt.Route{PeerID: 565, User: "dst-fallback", FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.121.8.0/24")}, AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.121.9.0/24")}})
		mustForwardNoLoop(pktAtoC, "owner-a")
		mustForwardNoLoop(pktCtoA, "owner-c")

		e.RemoveRoute(564)
		e.RemoveRoute(565)
		mustNoSelfLoopInLoopOnlyWindow(pktAtoC, "owner-a")
		mustNoSelfLoopInLoopOnlyWindow(pktCtoA, "owner-c")
	}

	m := e.SnapshotMetrics()
	if m.ControlUpsertOK == 0 || m.ControlRemoveOK == 0 || m.ControlErrors != 0 {
		t.Fatalf("unexpected metrics in bidirectional tie-churn guard: %+v", m)
	}
}

func TestEndpointBidirectionalSMBOwnerStepTiePrefixLoopOnlyDropMetrics(t *testing.T) {
	e := &Endpoint{
		engine:   rt.NewMemEngine(),
		peerUser: map[rt.RouteID]string{},
		userRef:  map[rt.SessionKey]int{},
		sessions: map[rt.SessionKey]N.PacketConn{},
	}
	for _, sk := range []rt.SessionKey{"owner-a", "owner-c", "dst-smb"} {
		e.enterSession(sk)
	}
	t.Cleanup(func() {
		for _, sk := range []rt.SessionKey{"dst-smb", "owner-c", "owner-a"} {
			e.leaveSession(sk)
		}
	})
	mustUpsert := func(r rt.Route) {
		t.Helper()
		if err := e.UpsertRoute(r); err != nil {
			t.Fatalf("upsert peer %d (%s): %v", r.PeerID, r.User, err)
		}
	}
	mustForwardNoLoop := func(pkt []byte, ingress rt.SessionKey) {
		t.Helper()
		d := e.handleIngressSession(pkt, ingress)
		if d.Action != rt.ActionForward {
			t.Fatalf("expected forward for %s, got %+v", ingress, d)
		}
		if d.EgressSession == ingress {
			t.Fatalf("unexpected self-loop for %s: %+v", ingress, d)
		}
	}
	mustNoSelfLoopInLoopOnlyWindow := func(pkt []byte, ingress rt.SessionKey) {
		t.Helper()
		d := e.handleIngressSession(pkt, ingress)
		if d.Action != rt.ActionDrop && d.Action != rt.ActionForward {
			t.Fatalf("expected forward/drop in loop-only window for %s, got %+v", ingress, d)
		}
		if d.EgressSession == ingress {
			t.Fatalf("unexpected self-egress for %s in loop-only window: %+v", ingress, d)
		}
	}

	mustUpsert(rt.Route{PeerID: 580, User: "owner-a", FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.131.0.0/24")}, FilterDestinationIPs: []netip.Prefix{netip.MustParsePrefix("10.131.9.0/24")}, AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.131.0.0/24")}})
	mustUpsert(rt.Route{PeerID: 581, User: "owner-c", FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.131.2.0/24")}, FilterDestinationIPs: []netip.Prefix{netip.MustParsePrefix("10.131.9.0/24")}, AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.131.2.0/24")}})
	mustUpsert(rt.Route{PeerID: 582, User: "owner-a", FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.131.0.0/24")}, AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.131.9.10/32")}})
	mustUpsert(rt.Route{PeerID: 583, User: "owner-c", FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.131.2.0/24")}, AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.131.9.11/32")}})
	mustUpsert(rt.Route{PeerID: 584, User: "dst-smb", FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.131.9.0/24")}, AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.131.9.0/24")}})

	pktAtoC := makeIPv4([4]byte{10, 131, 0, 10}, [4]byte{10, 131, 9, 11})
	pktCtoA := makeIPv4([4]byte{10, 131, 2, 10}, [4]byte{10, 131, 9, 10})
	for i := 0; i < 3; i++ {
		mustUpsert(rt.Route{PeerID: 584, User: "dst-smb", FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.131.9.0/24")}, AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.131.9.0/24")}})
		mustForwardNoLoop(pktAtoC, "owner-a")
		mustForwardNoLoop(pktCtoA, "owner-c")

		e.RemoveRoute(584)
		mustNoSelfLoopInLoopOnlyWindow(pktAtoC, "owner-a")
		mustNoSelfLoopInLoopOnlyWindow(pktCtoA, "owner-c")
	}

	m := e.SnapshotMetrics()
	if m.ControlUpsertOK == 0 || m.ControlRemoveOK == 0 || m.ControlErrors != 0 {
		t.Fatalf("unexpected metrics in bidirectional owner-step loop-only guard: %+v", m)
	}
}

func TestEndpointBidirectionalSMBAuthSymptomOwnerStepStaleEgressChurnTracksMetrics(t *testing.T) {
	e := &Endpoint{
		engine:   rt.NewMemEngine(),
		peerUser: map[rt.RouteID]string{},
		userRef:  map[rt.SessionKey]int{},
		sessions: map[rt.SessionKey]N.PacketConn{},
	}
	for _, sk := range []rt.SessionKey{"owner-a", "owner-c", "dst-smb"} {
		e.enterSession(sk)
	}
	t.Cleanup(func() {
		for _, sk := range []rt.SessionKey{"dst-smb", "owner-c", "owner-a"} {
			e.leaveSession(sk)
		}
	})
	mustUpsert := func(r rt.Route) {
		t.Helper()
		if err := e.UpsertRoute(r); err != nil {
			t.Fatalf("upsert peer %d (%s): %v", r.PeerID, r.User, err)
		}
	}
	mustForwardNoLoop := func(pkt []byte, ingress rt.SessionKey) {
		t.Helper()
		d := e.handleIngressSession(pkt, ingress)
		if d.Action != rt.ActionForward {
			t.Fatalf("expected forward for %s, got %+v", ingress, d)
		}
		if d.EgressSession == ingress {
			t.Fatalf("unexpected self-loop for %s: %+v", ingress, d)
		}
	}
	mustNoSelfEgressInStaleWindow := func(pkt []byte, ingress rt.SessionKey) {
		t.Helper()
		d := e.handleIngressSession(pkt, ingress)
		if d.Action != rt.ActionDrop && d.Action != rt.ActionForward {
			t.Fatalf("expected forward/drop in stale egress window for %s, got %+v", ingress, d)
		}
		if d.EgressSession == ingress {
			t.Fatalf("unexpected self-egress in stale window for %s: %+v", ingress, d)
		}
	}

	mustUpsert(rt.Route{PeerID: 590, User: "owner-a", FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.141.0.0/24")}, FilterDestinationIPs: []netip.Prefix{netip.MustParsePrefix("10.141.9.0/24")}, AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.141.0.0/24")}})
	mustUpsert(rt.Route{PeerID: 591, User: "owner-c", FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.141.2.0/24")}, FilterDestinationIPs: []netip.Prefix{netip.MustParsePrefix("10.141.9.0/24")}, AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.141.2.0/24")}})
	mustUpsert(rt.Route{PeerID: 592, User: "owner-a", FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.141.0.0/24")}, AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.141.9.10/32")}})
	mustUpsert(rt.Route{PeerID: 593, User: "owner-c", FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.141.2.0/24")}, AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.141.9.11/32")}})
	mustUpsert(rt.Route{PeerID: 594, User: "dst-smb", FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.141.9.0/24")}, AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.141.9.0/24")}})

	pktAtoC := makeIPv4([4]byte{10, 141, 0, 10}, [4]byte{10, 141, 9, 11})
	pktCtoA := makeIPv4([4]byte{10, 141, 2, 10}, [4]byte{10, 141, 9, 10})
	for i := 0; i < 4; i++ {
		mustUpsert(rt.Route{PeerID: 594, User: "dst-smb", FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.141.9.0/24")}, AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.141.9.0/24")}})
		mustForwardNoLoop(pktAtoC, "owner-a")
		mustForwardNoLoop(pktCtoA, "owner-c")

		if i%2 == 0 {
			e.clearEgressSessionForTesting(594)
		} else {
			e.RemoveRoute(594)
		}
		mustNoSelfEgressInStaleWindow(pktAtoC, "owner-a")
		mustNoSelfEgressInStaleWindow(pktCtoA, "owner-c")
	}

	m := e.SnapshotMetrics()
	if m.ControlUpsertOK == 0 || m.ControlRemoveOK == 0 || m.ControlErrors != 0 {
		t.Fatalf("unexpected metrics in bidirectional smb stale-egress guard: %+v", m)
	}
}

func TestEndpointBidirectionalSMBOwnerStepClearSessionStaleWindowTracksMetrics(t *testing.T) {
	e := &Endpoint{
		engine:   rt.NewMemEngine(),
		peerUser: map[rt.RouteID]string{},
		userRef:  map[rt.SessionKey]int{},
		sessions: map[rt.SessionKey]N.PacketConn{},
	}
	for _, sk := range []rt.SessionKey{"owner-a", "owner-b", "owner-c", "dst-smb"} {
		e.enterSession(sk)
	}
	t.Cleanup(func() {
		for _, sk := range []rt.SessionKey{"dst-smb", "owner-c", "owner-b", "owner-a"} {
			e.leaveSession(sk)
		}
	})
	mustUpsert := func(r rt.Route) {
		t.Helper()
		if err := e.UpsertRoute(r); err != nil {
			t.Fatalf("upsert peer %d (%s): %v", r.PeerID, r.User, err)
		}
	}
	mustForwardNoLoop := func(pkt []byte, ingress rt.SessionKey) {
		t.Helper()
		d := e.handleIngressSession(pkt, ingress)
		if d.Action != rt.ActionForward {
			t.Fatalf("expected forward for %s, got %+v", ingress, d)
		}
		if d.EgressSession == ingress {
			t.Fatalf("unexpected self-loop for %s: %+v", ingress, d)
		}
	}
	mustNoSelfEgressInStaleWindow := func(pkt []byte, ingress rt.SessionKey) {
		t.Helper()
		d := e.handleIngressSession(pkt, ingress)
		if d.Action != rt.ActionDrop && d.Action != rt.ActionForward {
			t.Fatalf("expected forward/drop in stale window for %s, got %+v", ingress, d)
		}
		if d.EgressSession == ingress {
			t.Fatalf("unexpected self-egress in stale window for %s: %+v", ingress, d)
		}
	}
	mustDrop := func(pkt []byte, ingress rt.SessionKey) {
		t.Helper()
		if d := e.handleIngressSession(pkt, ingress); d.Action != rt.ActionDrop {
			t.Fatalf("expected drop for %s, got %+v", ingress, d)
		}
	}

	mustUpsert(rt.Route{PeerID: 610, User: "owner-a", FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.151.0.0/24")}, FilterDestinationIPs: []netip.Prefix{netip.MustParsePrefix("10.151.9.0/24")}, AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.151.0.0/24")}})
	mustUpsert(rt.Route{PeerID: 611, User: "owner-a", FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.151.0.0/24")}, AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.151.9.10/32")}})
	mustUpsert(rt.Route{PeerID: 612, User: "owner-c", FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.151.2.0/24")}, AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.151.9.11/32")}})
	mustUpsert(rt.Route{PeerID: 613, User: "dst-smb", FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.151.9.0/24")}, AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.151.9.0/24")}})

	type step struct {
		owner rt.SessionKey
		src   [4]byte
		dst   [4]byte
		cidr  string
		stale rt.SessionKey
	}
	steps := []step{
		{owner: "owner-a", src: [4]byte{10, 151, 0, 10}, dst: [4]byte{10, 151, 9, 11}, cidr: "10.151.0.0/24"},
		{owner: "owner-b", src: [4]byte{10, 151, 1, 10}, dst: [4]byte{10, 151, 9, 10}, cidr: "10.151.1.0/24", stale: "owner-a"},
		{owner: "owner-c", src: [4]byte{10, 151, 2, 10}, dst: [4]byte{10, 151, 9, 11}, cidr: "10.151.2.0/24", stale: "owner-b"},
	}

	for i, s := range steps {
		mustUpsert(rt.Route{
			PeerID:               610,
			User:                 string(s.owner),
			FilterSourceIPs:      []netip.Prefix{netip.MustParsePrefix(s.cidr)},
			FilterDestinationIPs: []netip.Prefix{netip.MustParsePrefix("10.151.9.0/24")},
			AllowedIPs:           []netip.Prefix{netip.MustParsePrefix(s.cidr)},
		})

		mustForwardNoLoop(makeIPv4(s.src, s.dst), s.owner)
		if s.stale != "" {
			mustDrop(makeIPv4(steps[i-1].src, steps[i-1].dst), s.stale)
		}

		if i%2 == 0 {
			e.clearEgressSessionForTesting(613)
		} else {
			e.RemoveRoute(613)
		}
		mustNoSelfEgressInStaleWindow(makeIPv4(s.src, s.dst), s.owner)
		mustUpsert(rt.Route{PeerID: 613, User: "dst-smb", FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.151.9.0/24")}, AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.151.9.0/24")}})
	}

	m := e.SnapshotMetrics()
	if m.ControlUpsertOK == 0 || m.ControlRemoveOK == 0 || m.ControlErrors != 0 {
		t.Fatalf("unexpected metrics in bidirectional owner-step clear-session stale window: %+v", m)
	}
}

func TestEndpointBidirectionalSMBOwnerStepStaleRouteReaddWithIngressClearTracksMetrics(t *testing.T) {
	e := &Endpoint{
		engine:   rt.NewMemEngine(),
		peerUser: map[rt.RouteID]string{},
		userRef:  map[rt.SessionKey]int{},
		sessions: map[rt.SessionKey]N.PacketConn{},
	}
	for _, sk := range []rt.SessionKey{"owner-a", "owner-b", "owner-c", "dst-smb"} {
		e.enterSession(sk)
	}
	t.Cleanup(func() {
		for _, sk := range []rt.SessionKey{"dst-smb", "owner-c", "owner-b", "owner-a"} {
			e.leaveSession(sk)
		}
	})
	mustUpsert := func(r rt.Route) {
		t.Helper()
		if err := e.UpsertRoute(r); err != nil {
			t.Fatalf("upsert peer %d (%s): %v", r.PeerID, r.User, err)
		}
	}
	mustForwardNoLoop := func(pkt []byte, ingress rt.SessionKey) {
		t.Helper()
		d := e.handleIngressSession(pkt, ingress)
		if d.Action != rt.ActionForward {
			t.Fatalf("expected forward for %s, got %+v", ingress, d)
		}
		if d.EgressSession == ingress {
			t.Fatalf("unexpected self-loop for %s: %+v", ingress, d)
		}
	}
	mustNoSelfEgressInStaleWindow := func(pkt []byte, ingress rt.SessionKey) {
		t.Helper()
		d := e.handleIngressSession(pkt, ingress)
		if d.Action != rt.ActionDrop && d.Action != rt.ActionForward {
			t.Fatalf("expected forward/drop in stale window for %s, got %+v", ingress, d)
		}
		if d.EgressSession == ingress {
			t.Fatalf("unexpected self-egress in stale window for %s: %+v", ingress, d)
		}
	}
	mustDrop := func(pkt []byte, ingress rt.SessionKey) {
		t.Helper()
		if d := e.handleIngressSession(pkt, ingress); d.Action != rt.ActionDrop {
			t.Fatalf("expected drop for %s, got %+v", ingress, d)
		}
	}

	mustUpsert(rt.Route{PeerID: 620, User: "owner-a", FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.161.0.0/24")}, FilterDestinationIPs: []netip.Prefix{netip.MustParsePrefix("10.161.9.0/24")}, AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.161.0.0/24")}})
	mustUpsert(rt.Route{PeerID: 621, User: "owner-a", FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.161.0.0/24")}, AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.161.9.10/32")}})
	mustUpsert(rt.Route{PeerID: 622, User: "owner-c", FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.161.2.0/24")}, AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.161.9.11/32")}})
	mustUpsert(rt.Route{PeerID: 623, User: "dst-smb", FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.161.9.0/24")}, AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.161.9.0/24")}})

	type step struct {
		owner rt.SessionKey
		src   [4]byte
		dst   [4]byte
		cidr  string
		stale rt.SessionKey
	}
	steps := []step{
		{owner: "owner-a", src: [4]byte{10, 161, 0, 10}, dst: [4]byte{10, 161, 9, 11}, cidr: "10.161.0.0/24"},
		{owner: "owner-b", src: [4]byte{10, 161, 1, 10}, dst: [4]byte{10, 161, 9, 10}, cidr: "10.161.1.0/24", stale: "owner-a"},
		{owner: "owner-c", src: [4]byte{10, 161, 2, 10}, dst: [4]byte{10, 161, 9, 11}, cidr: "10.161.2.0/24", stale: "owner-b"},
	}

	for i, s := range steps {
		mustUpsert(rt.Route{
			PeerID:               620,
			User:                 string(s.owner),
			FilterSourceIPs:      []netip.Prefix{netip.MustParsePrefix(s.cidr)},
			FilterDestinationIPs: []netip.Prefix{netip.MustParsePrefix("10.161.9.0/24")},
			AllowedIPs:           []netip.Prefix{netip.MustParsePrefix(s.cidr)},
		})
		mustForwardNoLoop(makeIPv4(s.src, s.dst), s.owner)
		if s.stale != "" {
			mustDrop(makeIPv4(steps[i-1].src, steps[i-1].dst), s.stale)
		}

		e.clearIngressSessionForTesting(s.owner)
		e.RemoveRoute(623)
		e.setIngressSessionForTesting(620, s.owner)
		mustNoSelfEgressInStaleWindow(makeIPv4(s.src, s.dst), s.owner)

		mustUpsert(rt.Route{PeerID: 623, User: "dst-smb", FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.161.9.0/24")}, AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.161.9.0/24")}})
		mustForwardNoLoop(makeIPv4(s.src, s.dst), s.owner)
	}

	m := e.SnapshotMetrics()
	if m.ControlUpsertOK == 0 || m.ControlRemoveOK == 0 || m.ControlErrors != 0 {
		t.Fatalf("unexpected metrics in bidirectional owner-step stale-route-readd guard: %+v", m)
	}
}

func TestEndpointServerRestartStyleOwnerStepChurnMaintainsNoLoopAndMetrics(t *testing.T) {
	e := &Endpoint{
		engine:   rt.NewMemEngine(),
		peerUser: map[rt.RouteID]string{},
		userRef:  map[rt.SessionKey]int{},
		sessions: map[rt.SessionKey]N.PacketConn{},
	}
	for _, sk := range []rt.SessionKey{"owner-a", "owner-b", "owner-c", "dst-smb"} {
		e.enterSession(sk)
	}
	t.Cleanup(func() {
		for _, sk := range []rt.SessionKey{"dst-smb", "owner-c", "owner-b", "owner-a"} {
			e.leaveSession(sk)
		}
	})

	mustUpsert := func(r rt.Route) {
		t.Helper()
		if err := e.UpsertRoute(r); err != nil {
			t.Fatalf("upsert peer %d (%s): %v", r.PeerID, r.User, err)
		}
	}
	mustDrop := func(pkt []byte, ingress rt.SessionKey) {
		t.Helper()
		if d := e.handleIngressSession(pkt, ingress); d.Action != rt.ActionDrop {
			t.Fatalf("expected drop for %s, got %+v", ingress, d)
		}
	}
	mustForwardNoLoop := func(pkt []byte, ingress rt.SessionKey) {
		t.Helper()
		d := e.handleIngressSession(pkt, ingress)
		if d.Action != rt.ActionForward {
			t.Fatalf("expected forward for %s, got %+v", ingress, d)
		}
		if d.EgressSession == ingress {
			t.Fatalf("unexpected self-loop for %s: %+v", ingress, d)
		}
	}

	mustUpsert(rt.Route{PeerID: 710, User: "owner-a", FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.171.0.0/24")}, FilterDestinationIPs: []netip.Prefix{netip.MustParsePrefix("10.171.9.0/24")}, AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.171.0.0/24")}})
	mustUpsert(rt.Route{PeerID: 711, User: "dst-smb", FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.171.9.0/24")}, AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.171.9.0/24")}})
	mustUpsert(rt.Route{PeerID: 712, User: "backup-egress", FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.171.9.0/24")}, AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.171.9.0/24")}})

	type step struct {
		owner rt.SessionKey
		src   [4]byte
		cidr  string
	}
	steps := []step{
		{owner: "owner-a", src: [4]byte{10, 171, 0, 10}, cidr: "10.171.0.0/24"},
		{owner: "owner-b", src: [4]byte{10, 171, 1, 10}, cidr: "10.171.1.0/24"},
		{owner: "owner-c", src: [4]byte{10, 171, 2, 10}, cidr: "10.171.2.0/24"},
	}
	dst := [4]byte{10, 171, 9, 11}

	for i, s := range steps {
		mustUpsert(rt.Route{
			PeerID:               710,
			User:                 string(s.owner),
			FilterSourceIPs:      []netip.Prefix{netip.MustParsePrefix(s.cidr)},
			FilterDestinationIPs: []netip.Prefix{netip.MustParsePrefix("10.171.9.0/24")},
			AllowedIPs:           []netip.Prefix{netip.MustParsePrefix(s.cidr)},
		})

		// Restart-style churn window: routes are absent and forwarding must be dropped.
		e.RemoveRoute(711)
		e.RemoveRoute(712)
		mustDrop(makeIPv4(s.src, dst), s.owner)

		mustUpsert(rt.Route{PeerID: 711, User: "dst-smb", FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.171.9.0/24")}, AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.171.9.0/24")}})
		mustUpsert(rt.Route{PeerID: 712, User: "backup-egress", FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.171.9.0/24")}, AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.171.9.0/24")}})

		if i%2 == 0 {
			e.setEgressSessionForTesting(711, s.owner)
			e.setEgressSessionForTesting(712, "dst-smb")
		} else {
			e.setEgressSessionForTesting(711, "dst-smb")
			e.setEgressSessionForTesting(712, s.owner)
		}
		mustForwardNoLoop(makeIPv4(s.src, dst), s.owner)

		if i > 0 {
			prev := steps[i-1]
			mustDrop(makeIPv4(prev.src, dst), prev.owner)
		}
	}

	m := e.SnapshotMetrics()
	if m.ControlUpsertOK == 0 || m.ControlRemoveOK == 0 || m.ControlErrors != 0 {
		t.Fatalf("unexpected metrics in server-restart owner-step churn test: %+v", m)
	}
}

func TestEndpointServerRestartChurnSMBAuthSymptomGuardTracksMetrics(t *testing.T) {
	e := &Endpoint{
		engine:   rt.NewMemEngine(),
		peerUser: map[rt.RouteID]string{},
		userRef:  map[rt.SessionKey]int{},
		sessions: map[rt.SessionKey]N.PacketConn{},
	}
	for _, sk := range []rt.SessionKey{"owner-a", "owner-b", "owner-c", "dst-smb"} {
		e.enterSession(sk)
	}
	t.Cleanup(func() {
		for _, sk := range []rt.SessionKey{"dst-smb", "owner-c", "owner-b", "owner-a"} {
			e.leaveSession(sk)
		}
	})
	mustUpsert := func(r rt.Route) {
		t.Helper()
		if err := e.UpsertRoute(r); err != nil {
			t.Fatalf("upsert peer %d (%s): %v", r.PeerID, r.User, err)
		}
	}
	mustDrop := func(pkt []byte, ingress rt.SessionKey) {
		t.Helper()
		if d := e.handleIngressSession(pkt, ingress); d.Action != rt.ActionDrop {
			t.Fatalf("expected drop for %s, got %+v", ingress, d)
		}
	}
	mustForwardNoLoop := func(pkt []byte, ingress rt.SessionKey) {
		t.Helper()
		d := e.handleIngressSession(pkt, ingress)
		if d.Action != rt.ActionForward {
			t.Fatalf("expected forward for %s, got %+v", ingress, d)
		}
		if d.EgressSession == ingress {
			t.Fatalf("unexpected self-loop for %s: %+v", ingress, d)
		}
	}

	mustUpsert(rt.Route{PeerID: 720, User: "owner-a", FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.181.0.0/24")}, FilterDestinationIPs: []netip.Prefix{netip.MustParsePrefix("10.181.9.0/24")}, AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.181.0.0/24")}})
	mustUpsert(rt.Route{PeerID: 721, User: "dst-loop", FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.181.9.0/24")}, AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.181.9.0/24")}})
	mustUpsert(rt.Route{PeerID: 722, User: "dst-smb", FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.181.9.0/24")}, AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.181.9.0/24")}})

	type step struct {
		owner rt.SessionKey
		src   [4]byte
		cidr  string
	}
	steps := []step{
		{owner: "owner-a", src: [4]byte{10, 181, 0, 10}, cidr: "10.181.0.0/24"},
		{owner: "owner-b", src: [4]byte{10, 181, 1, 10}, cidr: "10.181.1.0/24"},
		{owner: "owner-c", src: [4]byte{10, 181, 2, 10}, cidr: "10.181.2.0/24"},
	}
	dst := [4]byte{10, 181, 9, 11}
	for i, s := range steps {
		mustUpsert(rt.Route{
			PeerID:               720,
			User:                 string(s.owner),
			FilterSourceIPs:      []netip.Prefix{netip.MustParsePrefix(s.cidr)},
			FilterDestinationIPs: []netip.Prefix{netip.MustParsePrefix("10.181.9.0/24")},
			AllowedIPs:           []netip.Prefix{netip.MustParsePrefix(s.cidr)},
		})
		e.RemoveRoute(721)
		e.RemoveRoute(722)
		mustDrop(makeIPv4(s.src, dst), s.owner)

		mustUpsert(rt.Route{PeerID: 721, User: "dst-loop", FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.181.9.0/24")}, AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.181.9.0/24")}})
		mustUpsert(rt.Route{PeerID: 722, User: "dst-smb", FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.181.9.0/24")}, AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.181.9.0/24")}})
		e.setEgressSessionForTesting(721, s.owner)
		e.setEgressSessionForTesting(722, "dst-smb")
		mustForwardNoLoop(makeIPv4(s.src, dst), s.owner)

		if i > 0 {
			prev := steps[i-1]
			mustDrop(makeIPv4(prev.src, dst), prev.owner)
		}
	}

	m := e.SnapshotMetrics()
	if m.ControlUpsertOK == 0 || m.ControlRemoveOK == 0 || m.ControlErrors != 0 {
		t.Fatalf("unexpected metrics in restart/churn smb symptom guard test: %+v", m)
	}
}

func TestEndpointServerRestartChurnOwnerStepEgressFlapNoLoopAndMetrics(t *testing.T) {
	e := &Endpoint{
		engine:   rt.NewMemEngine(),
		peerUser: map[rt.RouteID]string{},
		userRef:  map[rt.SessionKey]int{},
		sessions: map[rt.SessionKey]N.PacketConn{},
	}
	for _, sk := range []rt.SessionKey{"owner-a", "owner-b", "owner-c", "dst-smb"} {
		e.enterSession(sk)
	}
	t.Cleanup(func() {
		for _, sk := range []rt.SessionKey{"dst-smb", "owner-c", "owner-b", "owner-a"} {
			e.leaveSession(sk)
		}
	})
	mustUpsert := func(r rt.Route) {
		t.Helper()
		if err := e.UpsertRoute(r); err != nil {
			t.Fatalf("upsert peer %d (%s): %v", r.PeerID, r.User, err)
		}
	}
	mustDrop := func(pkt []byte, ingress rt.SessionKey) {
		t.Helper()
		if d := e.handleIngressSession(pkt, ingress); d.Action != rt.ActionDrop {
			t.Fatalf("expected drop for %s, got %+v", ingress, d)
		}
	}
	mustForwardNoLoop := func(pkt []byte, ingress rt.SessionKey) {
		t.Helper()
		d := e.handleIngressSession(pkt, ingress)
		if d.Action != rt.ActionForward {
			t.Fatalf("expected forward for %s, got %+v", ingress, d)
		}
		if d.EgressSession == ingress {
			t.Fatalf("unexpected self-loop for %s: %+v", ingress, d)
		}
	}

	mustUpsert(rt.Route{PeerID: 730, User: "owner-a", FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.191.0.0/24")}, FilterDestinationIPs: []netip.Prefix{netip.MustParsePrefix("10.191.9.0/24")}, AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.191.0.0/24")}})
	mustUpsert(rt.Route{PeerID: 731, User: "dst-loop", FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.191.9.0/24")}, AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.191.9.0/24")}})
	mustUpsert(rt.Route{PeerID: 732, User: "dst-smb", FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.191.9.0/24")}, AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.191.9.0/24")}})

	type step struct {
		owner rt.SessionKey
		src   [4]byte
		cidr  string
	}
	steps := []step{
		{owner: "owner-a", src: [4]byte{10, 191, 0, 10}, cidr: "10.191.0.0/24"},
		{owner: "owner-b", src: [4]byte{10, 191, 1, 10}, cidr: "10.191.1.0/24"},
		{owner: "owner-c", src: [4]byte{10, 191, 2, 10}, cidr: "10.191.2.0/24"},
	}
	dst := [4]byte{10, 191, 9, 11}
	for i, s := range steps {
		mustUpsert(rt.Route{
			PeerID:               730,
			User:                 string(s.owner),
			FilterSourceIPs:      []netip.Prefix{netip.MustParsePrefix(s.cidr)},
			FilterDestinationIPs: []netip.Prefix{netip.MustParsePrefix("10.191.9.0/24")},
			AllowedIPs:           []netip.Prefix{netip.MustParsePrefix(s.cidr)},
		})

		// Restart/churn loop-only window: keep only loop candidate.
		e.RemoveRoute(732)
		e.setEgressSessionForTesting(731, s.owner)
		mustDrop(makeIPv4(s.src, dst), s.owner)

		mustUpsert(rt.Route{PeerID: 732, User: "dst-smb", FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.191.9.0/24")}, AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.191.9.0/24")}})
		e.setEgressSessionForTesting(732, "dst-smb")
		mustForwardNoLoop(makeIPv4(s.src, dst), s.owner)

		if i > 0 {
			prev := steps[i-1]
			mustDrop(makeIPv4(prev.src, dst), prev.owner)
		}
	}

	m := e.SnapshotMetrics()
	if m.ControlUpsertOK == 0 || m.ControlRemoveOK == 0 || m.ControlErrors != 0 {
		t.Fatalf("unexpected metrics in restart/churn owner-step egress-flap guard test: %+v", m)
	}
}

func TestEndpointLoopbackSymptomDriftGatePatternTracksDropAndRecoveryMetrics(t *testing.T) {
	e := &Endpoint{
		engine:   rt.NewMemEngine(),
		peerUser: map[rt.RouteID]string{},
		userRef:  map[rt.SessionKey]int{},
		sessions: map[rt.SessionKey]N.PacketConn{},
	}
	for _, sk := range []rt.SessionKey{"owner-a", "dst-smb"} {
		e.enterSession(sk)
	}
	t.Cleanup(func() {
		for _, sk := range []rt.SessionKey{"dst-smb", "owner-a"} {
			e.leaveSession(sk)
		}
	})
	mustUpsert := func(r rt.Route) {
		t.Helper()
		if err := e.UpsertRoute(r); err != nil {
			t.Fatalf("upsert peer %d (%s): %v", r.PeerID, r.User, err)
		}
	}
	mustDrop := func(pkt []byte, ingress rt.SessionKey) {
		t.Helper()
		if d := e.handleIngressSession(pkt, ingress); d.Action != rt.ActionDrop {
			t.Fatalf("expected drop for %s, got %+v", ingress, d)
		}
	}
	mustForwardNoLoop := func(pkt []byte, ingress rt.SessionKey) {
		t.Helper()
		d := e.handleIngressSession(pkt, ingress)
		if d.Action != rt.ActionForward {
			t.Fatalf("expected forward for %s, got %+v", ingress, d)
		}
		if d.EgressSession == ingress {
			t.Fatalf("unexpected self-loop for %s: %+v", ingress, d)
		}
	}

	mustUpsert(rt.Route{PeerID: 740, User: "owner-a", FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.210.0.0/24")}, FilterDestinationIPs: []netip.Prefix{netip.MustParsePrefix("10.210.9.0/24")}, AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.210.0.0/24")}})
	mustUpsert(rt.Route{PeerID: 741, User: "dst-loop", FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.210.9.0/24")}, AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.210.9.0/24")}})
	mustUpsert(rt.Route{PeerID: 742, User: "dst-smb", FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.210.9.0/24")}, AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.210.9.0/24")}})

	src := [4]byte{10, 210, 0, 10}
	dst := [4]byte{10, 210, 9, 11}
	pkt := makeIPv4(src, dst)

	e.setEgressSessionForTesting(741, "owner-a")
	e.RemoveRoute(742)
	mustDrop(pkt, "owner-a")

	mustUpsert(rt.Route{PeerID: 742, User: "dst-smb", FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.210.9.0/24")}, AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.210.9.0/24")}})
	e.setEgressSessionForTesting(742, "dst-smb")
	mustForwardNoLoop(pkt, "owner-a")

	m := e.SnapshotMetrics()
	if m.ControlUpsertOK == 0 || m.ControlRemoveOK == 0 || m.ControlErrors != 0 {
		t.Fatalf("unexpected control-plane metrics in loopback symptom drift test: %+v", m)
	}
}

func TestEndpointLoopbackSymptomGuardWithNTStatusLikeChurnTracksNoLoopMetrics(t *testing.T) {
	e := &Endpoint{
		engine:   rt.NewMemEngine(),
		peerUser: map[rt.RouteID]string{},
		userRef:  map[rt.SessionKey]int{},
		sessions: map[rt.SessionKey]N.PacketConn{},
	}
	for _, sk := range []rt.SessionKey{"owner-a", "owner-b", "owner-c", "dst-smb"} {
		e.enterSession(sk)
	}
	t.Cleanup(func() {
		for _, sk := range []rt.SessionKey{"dst-smb", "owner-c", "owner-b", "owner-a"} {
			e.leaveSession(sk)
		}
	})
	mustUpsert := func(r rt.Route) {
		t.Helper()
		if err := e.UpsertRoute(r); err != nil {
			t.Fatalf("upsert peer %d (%s): %v", r.PeerID, r.User, err)
		}
	}
	mustForwardNoLoop := func(pkt []byte, ingress rt.SessionKey) {
		t.Helper()
		d := e.handleIngressSession(pkt, ingress)
		if d.Action != rt.ActionForward {
			t.Fatalf("expected forward for %s, got %+v", ingress, d)
		}
		if d.EgressSession == ingress {
			t.Fatalf("unexpected self-loop for %s: %+v", ingress, d)
		}
	}
	mustDrop := func(pkt []byte, ingress rt.SessionKey) {
		t.Helper()
		if d := e.handleIngressSession(pkt, ingress); d.Action != rt.ActionDrop {
			t.Fatalf("expected drop for %s, got %+v", ingress, d)
		}
	}

	mustUpsert(rt.Route{PeerID: 750, User: "owner-a", FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.212.0.0/24")}, FilterDestinationIPs: []netip.Prefix{netip.MustParsePrefix("10.212.9.0/24")}, AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.212.0.0/24")}})
	mustUpsert(rt.Route{PeerID: 751, User: "dst-loop", FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.212.9.0/24")}, AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.212.9.0/24")}})
	mustUpsert(rt.Route{PeerID: 752, User: "dst-smb", FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.212.9.0/24")}, AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.212.9.0/24")}})
	e.setEgressSessionForTesting(752, "dst-smb")

	type step struct {
		owner rt.SessionKey
		src   [4]byte
		cidr  string
	}
	steps := []step{
		{owner: "owner-a", src: [4]byte{10, 212, 0, 10}, cidr: "10.212.0.0/24"},
		{owner: "owner-b", src: [4]byte{10, 212, 1, 10}, cidr: "10.212.1.0/24"},
		{owner: "owner-c", src: [4]byte{10, 212, 2, 10}, cidr: "10.212.2.0/24"},
	}
	dst := [4]byte{10, 212, 9, 11}
	for i, s := range steps {
		mustUpsert(rt.Route{
			PeerID:               750,
			User:                 string(s.owner),
			FilterSourceIPs:      []netip.Prefix{netip.MustParsePrefix(s.cidr)},
			FilterDestinationIPs: []netip.Prefix{netip.MustParsePrefix("10.212.9.0/24")},
			AllowedIPs:           []netip.Prefix{netip.MustParsePrefix(s.cidr)},
		})
		e.setEgressSessionForTesting(751, s.owner)
		mustForwardNoLoop(makeIPv4(s.src, dst), s.owner)
		if i > 0 {
			prev := steps[i-1]
			mustDrop(makeIPv4(prev.src, dst), prev.owner)
		}
	}

	m := e.SnapshotMetrics()
	if m.ControlUpsertOK == 0 || m.ControlErrors != 0 {
		t.Fatalf("unexpected control-plane metrics in nt-status-like churn guard test: %+v", m)
	}
}

func TestEndpointOwnerStepFalsePositiveAuthSymptomGuardTraceKeepsNoLoopAndMetrics(t *testing.T) {
	e := &Endpoint{
		engine:   rt.NewMemEngine(),
		peerUser: map[rt.RouteID]string{},
		userRef:  map[rt.SessionKey]int{},
		sessions: map[rt.SessionKey]N.PacketConn{},
	}
	for _, sk := range []rt.SessionKey{"owner-a", "owner-b", "owner-c", "dst-smb"} {
		e.enterSession(sk)
	}
	t.Cleanup(func() {
		for _, sk := range []rt.SessionKey{"dst-smb", "owner-c", "owner-b", "owner-a"} {
			e.leaveSession(sk)
		}
	})
	mustUpsert := func(r rt.Route) {
		t.Helper()
		if err := e.UpsertRoute(r); err != nil {
			t.Fatalf("upsert peer %d (%s): %v", r.PeerID, r.User, err)
		}
	}
	mustForwardNoLoop := func(pkt []byte, ingress rt.SessionKey) {
		t.Helper()
		d := e.handleIngressSession(pkt, ingress)
		if d.Action != rt.ActionForward {
			t.Fatalf("expected forward for %s, got %+v", ingress, d)
		}
		if d.EgressSession == ingress {
			t.Fatalf("unexpected self-loop for %s: %+v", ingress, d)
		}
	}
	mustDrop := func(pkt []byte, ingress rt.SessionKey) {
		t.Helper()
		if d := e.handleIngressSession(pkt, ingress); d.Action != rt.ActionDrop {
			t.Fatalf("expected drop for %s, got %+v", ingress, d)
		}
	}

	mustUpsert(rt.Route{PeerID: 760, User: "owner-a", FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.214.0.0/24")}, FilterDestinationIPs: []netip.Prefix{netip.MustParsePrefix("10.214.9.0/24")}, AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.214.0.0/24")}})
	mustUpsert(rt.Route{PeerID: 761, User: "dst-loop", FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.214.9.0/24")}, AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.214.9.0/24")}})
	mustUpsert(rt.Route{PeerID: 762, User: "dst-smb", FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.214.9.0/24")}, AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.214.9.0/24")}})
	e.setEgressSessionForTesting(762, "dst-smb")

	type step struct {
		owner rt.SessionKey
		src   [4]byte
		cidr  string
	}
	steps := []step{
		{owner: "owner-a", src: [4]byte{10, 214, 0, 10}, cidr: "10.214.0.0/24"},
		{owner: "owner-b", src: [4]byte{10, 214, 1, 10}, cidr: "10.214.1.0/24"},
		{owner: "owner-c", src: [4]byte{10, 214, 2, 10}, cidr: "10.214.2.0/24"},
	}
	dst := [4]byte{10, 214, 9, 11}
	for i, s := range steps {
		mustUpsert(rt.Route{
			PeerID:               760,
			User:                 string(s.owner),
			FilterSourceIPs:      []netip.Prefix{netip.MustParsePrefix(s.cidr)},
			FilterDestinationIPs: []netip.Prefix{netip.MustParsePrefix("10.214.9.0/24")},
			AllowedIPs:           []netip.Prefix{netip.MustParsePrefix(s.cidr)},
		})
		e.setEgressSessionForTesting(761, s.owner) // loop candidate for false-positive window
		mustForwardNoLoop(makeIPv4(s.src, dst), s.owner)
		if i > 0 {
			prev := steps[i-1]
			mustDrop(makeIPv4(prev.src, dst), prev.owner)
		}
	}

	m := e.SnapshotMetrics()
	if m.ControlUpsertOK == 0 || m.ControlErrors != 0 {
		t.Fatalf("unexpected control-plane metrics in false-positive auth symptom guard test: %+v", m)
	}
}

func TestEndpointOwnerStepFalsePositiveGuardReasonHistogramTraceMetrics(t *testing.T) {
	e := &Endpoint{
		engine:   rt.NewMemEngine(),
		peerUser: map[rt.RouteID]string{},
		userRef:  map[rt.SessionKey]int{},
		sessions: map[rt.SessionKey]N.PacketConn{},
	}
	for _, sk := range []rt.SessionKey{"owner-a", "owner-b", "owner-c", "dst-smb"} {
		e.enterSession(sk)
	}
	t.Cleanup(func() {
		for _, sk := range []rt.SessionKey{"dst-smb", "owner-c", "owner-b", "owner-a"} {
			e.leaveSession(sk)
		}
	})

	mustUpsert := func(r rt.Route) {
		t.Helper()
		if err := e.UpsertRoute(r); err != nil {
			t.Fatalf("upsert peer %d (%s): %v", r.PeerID, r.User, err)
		}
	}
	mustForwardNoLoop := func(pkt []byte, ingress rt.SessionKey) {
		t.Helper()
		d := e.handleIngressSession(pkt, ingress)
		if d.Action != rt.ActionForward {
			t.Fatalf("expected forward for %s, got %+v", ingress, d)
		}
		if d.EgressSession == ingress {
			t.Fatalf("unexpected self-loop for %s: %+v", ingress, d)
		}
	}
	mustDrop := func(pkt []byte, ingress rt.SessionKey) {
		t.Helper()
		if d := e.handleIngressSession(pkt, ingress); d.Action != rt.ActionDrop {
			t.Fatalf("expected drop for %s, got %+v", ingress, d)
		}
	}

	mustUpsert(rt.Route{PeerID: 770, User: "owner-a", FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.216.0.0/24")}, FilterDestinationIPs: []netip.Prefix{netip.MustParsePrefix("10.216.9.0/24")}, AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.216.0.0/24")}})
	mustUpsert(rt.Route{PeerID: 771, User: "dst-loop", FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.216.9.0/24")}, AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.216.9.0/24")}})
	mustUpsert(rt.Route{PeerID: 772, User: "dst-smb", FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.216.9.0/24")}, AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.216.9.0/24")}})
	e.setEgressSessionForTesting(772, "dst-smb")

	type step struct {
		owner rt.SessionKey
		src   [4]byte
		cidr  string
	}
	steps := []step{
		{owner: "owner-a", src: [4]byte{10, 216, 0, 10}, cidr: "10.216.0.0/24"},
		{owner: "owner-b", src: [4]byte{10, 216, 1, 10}, cidr: "10.216.1.0/24"},
		{owner: "owner-c", src: [4]byte{10, 216, 2, 10}, cidr: "10.216.2.0/24"},
	}
	dst := [4]byte{10, 216, 9, 11}
	for i, s := range steps {
		mustUpsert(rt.Route{
			PeerID:               770,
			User:                 string(s.owner),
			FilterSourceIPs:      []netip.Prefix{netip.MustParsePrefix(s.cidr)},
			FilterDestinationIPs: []netip.Prefix{netip.MustParsePrefix("10.216.9.0/24")},
			AllowedIPs:           []netip.Prefix{netip.MustParsePrefix(s.cidr)},
		})
		e.setEgressSessionForTesting(771, s.owner)
		mustForwardNoLoop(makeIPv4(s.src, dst), s.owner)

		// Loop-only window must never produce self-forwarding.
		e.RemoveRoute(772)
		mustDrop(makeIPv4(s.src, dst), s.owner)
		mustUpsert(rt.Route{PeerID: 772, User: "dst-smb", FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.216.9.0/24")}, AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.216.9.0/24")}})
		e.setEgressSessionForTesting(772, "dst-smb")

		if i > 0 {
			prev := steps[i-1]
			mustDrop(makeIPv4(prev.src, dst), prev.owner)
		}
	}

	m := e.SnapshotMetrics()
	if m.ControlUpsertOK == 0 || m.ControlRemoveOK == 0 || m.ControlErrors != 0 {
		t.Fatalf("unexpected control-plane metrics in false-positive guard histogram test: %+v", m)
	}
}

func TestEndpointOwnerStepGuardSeveritySplitLoopOnlyWindowTracksMetrics(t *testing.T) {
	e := &Endpoint{
		engine:   rt.NewMemEngine(),
		peerUser: map[rt.RouteID]string{},
		userRef:  map[rt.SessionKey]int{},
		sessions: map[rt.SessionKey]N.PacketConn{},
	}
	for _, sk := range []rt.SessionKey{"owner-a", "owner-b", "owner-c", "dst-loop", "dst-smb"} {
		e.enterSession(sk)
	}
	t.Cleanup(func() {
		for _, sk := range []rt.SessionKey{"dst-smb", "dst-loop", "owner-c", "owner-b", "owner-a"} {
			e.leaveSession(sk)
		}
	})

	mustUpsert := func(r rt.Route) {
		t.Helper()
		if err := e.UpsertRoute(r); err != nil {
			t.Fatalf("upsert peer %d (%s): %v", r.PeerID, r.User, err)
		}
	}
	mustForwardNoLoop := func(pkt []byte, ingress rt.SessionKey) {
		t.Helper()
		d := e.handleIngressSession(pkt, ingress)
		if d.Action != rt.ActionForward {
			t.Fatalf("expected forward for %s, got %+v", ingress, d)
		}
		if d.EgressSession == ingress {
			t.Fatalf("unexpected self-loop for %s: %+v", ingress, d)
		}
	}
	mustDrop := func(pkt []byte, ingress rt.SessionKey) {
		t.Helper()
		if d := e.handleIngressSession(pkt, ingress); d.Action != rt.ActionDrop {
			t.Fatalf("expected drop for %s, got %+v", ingress, d)
		}
	}

	mustUpsert(rt.Route{PeerID: 780, User: "owner-a", FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.231.0.0/24")}, FilterDestinationIPs: []netip.Prefix{netip.MustParsePrefix("10.231.9.0/24")}, AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.231.0.0/24")}})
	mustUpsert(rt.Route{PeerID: 781, User: "dst-loop", FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.231.9.0/24")}, AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.231.9.0/24")}})
	mustUpsert(rt.Route{PeerID: 782, User: "dst-smb", FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.231.9.0/24")}, AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.231.9.0/24")}})
	e.setEgressSessionForTesting(782, "dst-smb")

	steps := []struct {
		owner rt.SessionKey
		src   [4]byte
		cidr  string
	}{
		{owner: "owner-a", src: [4]byte{10, 231, 0, 10}, cidr: "10.231.0.0/24"},
		{owner: "owner-b", src: [4]byte{10, 231, 1, 10}, cidr: "10.231.1.0/24"},
		{owner: "owner-c", src: [4]byte{10, 231, 2, 10}, cidr: "10.231.2.0/24"},
	}
	dst := [4]byte{10, 231, 9, 10}
	for i, s := range steps {
		mustUpsert(rt.Route{
			PeerID:               780,
			User:                 string(s.owner),
			FilterSourceIPs:      []netip.Prefix{netip.MustParsePrefix(s.cidr)},
			FilterDestinationIPs: []netip.Prefix{netip.MustParsePrefix("10.231.9.0/24")},
			AllowedIPs:           []netip.Prefix{netip.MustParsePrefix(s.cidr)},
		})
		e.setEgressSessionForTesting(781, s.owner)
		mustForwardNoLoop(makeIPv4(s.src, dst), s.owner)

		e.RemoveRoute(782)
		mustDrop(makeIPv4(s.src, dst), s.owner)
		mustUpsert(rt.Route{PeerID: 782, User: "dst-smb", FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.231.9.0/24")}, AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.231.9.0/24")}})
		e.setEgressSessionForTesting(782, "dst-smb")
		mustForwardNoLoop(makeIPv4(s.src, dst), s.owner)

		if i > 0 {
			prev := steps[i-1]
			mustDrop(makeIPv4(prev.src, dst), prev.owner)
		}
	}

	m := e.SnapshotMetrics()
	if m.ControlUpsertOK != 9 || m.ControlRemoveOK != 3 || m.ControlErrors != 0 {
		t.Fatalf("unexpected metrics in guard-severity split loop-window test: %+v", m)
	}
}

func TestEndpointOwnerStepSeverityTraceAtoBtoCNoLoopAcrossLiveAndStallMetrics(t *testing.T) {
	e := &Endpoint{
		engine:   rt.NewMemEngine(),
		peerUser: map[rt.RouteID]string{},
		userRef:  map[rt.SessionKey]int{},
		sessions: map[rt.SessionKey]N.PacketConn{},
	}
	for _, sk := range []rt.SessionKey{"owner-a", "owner-b", "owner-c", "dst-loop", "dst-smb"} {
		e.enterSession(sk)
	}
	t.Cleanup(func() {
		for _, sk := range []rt.SessionKey{"dst-smb", "dst-loop", "owner-c", "owner-b", "owner-a"} {
			e.leaveSession(sk)
		}
	})

	mustUpsert := func(r rt.Route) {
		t.Helper()
		if err := e.UpsertRoute(r); err != nil {
			t.Fatalf("upsert peer %d (%s): %v", r.PeerID, r.User, err)
		}
	}
	mustForwardNoLoop := func(pkt []byte, ingress rt.SessionKey) {
		t.Helper()
		d := e.handleIngressSession(pkt, ingress)
		if d.Action != rt.ActionForward {
			t.Fatalf("expected forward for %s, got %+v", ingress, d)
		}
		if d.EgressSession == ingress {
			t.Fatalf("unexpected self-loop for %s: %+v", ingress, d)
		}
	}
	mustDrop := func(pkt []byte, ingress rt.SessionKey) {
		t.Helper()
		if d := e.handleIngressSession(pkt, ingress); d.Action != rt.ActionDrop {
			t.Fatalf("expected drop for %s, got %+v", ingress, d)
		}
	}

	mustUpsert(rt.Route{PeerID: 790, User: "owner-a", FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.233.0.0/24")}, FilterDestinationIPs: []netip.Prefix{netip.MustParsePrefix("10.233.9.0/24")}, AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.233.0.0/24")}})
	mustUpsert(rt.Route{PeerID: 791, User: "dst-loop", FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.233.9.0/24")}, AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.233.9.0/24")}})
	mustUpsert(rt.Route{PeerID: 792, User: "dst-smb", FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.233.9.0/24")}, AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.233.9.0/24")}})
	e.setEgressSessionForTesting(792, "dst-smb")

	steps := []struct {
		owner rt.SessionKey
		src   [4]byte
		cidr  string
	}{
		{owner: "owner-a", src: [4]byte{10, 233, 0, 10}, cidr: "10.233.0.0/24"},
		{owner: "owner-b", src: [4]byte{10, 233, 1, 10}, cidr: "10.233.1.0/24"},
		{owner: "owner-c", src: [4]byte{10, 233, 2, 10}, cidr: "10.233.2.0/24"},
	}
	dst := [4]byte{10, 233, 9, 10}
	for i, s := range steps {
		mustUpsert(rt.Route{
			PeerID:               790,
			User:                 string(s.owner),
			FilterSourceIPs:      []netip.Prefix{netip.MustParsePrefix(s.cidr)},
			FilterDestinationIPs: []netip.Prefix{netip.MustParsePrefix("10.233.9.0/24")},
			AllowedIPs:           []netip.Prefix{netip.MustParsePrefix(s.cidr)},
		})
		e.setEgressSessionForTesting(791, s.owner)
		mustForwardNoLoop(makeIPv4(s.src, dst), s.owner)

		e.RemoveRoute(792)
		mustDrop(makeIPv4(s.src, dst), s.owner)
		mustUpsert(rt.Route{PeerID: 792, User: "dst-smb", FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.233.9.0/24")}, AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.233.9.0/24")}})
		e.setEgressSessionForTesting(792, "dst-smb")
		mustForwardNoLoop(makeIPv4(s.src, dst), s.owner)

		if i > 0 {
			prev := steps[i-1]
			mustDrop(makeIPv4(prev.src, dst), prev.owner)
		}
	}

	m := e.SnapshotMetrics()
	if m.ControlUpsertOK != 9 || m.ControlRemoveOK != 3 || m.ControlErrors != 0 {
		t.Fatalf("unexpected metrics in severity-trace no-loop test: %+v", m)
	}
}

func TestEndpointOwnerStepDataplaneStallWindowIncrementsDropMetrics(t *testing.T) {
	e := &Endpoint{
		engine:   rt.NewMemEngine(),
		peerUser: map[rt.RouteID]string{},
		userRef:  map[rt.SessionKey]int{},
		sessions: map[rt.SessionKey]N.PacketConn{},
	}
	for _, sk := range []rt.SessionKey{"owner-a", "owner-b", "owner-c", "dst-loop", "dst-smb"} {
		e.enterSession(sk)
	}
	t.Cleanup(func() {
		for _, sk := range []rt.SessionKey{"dst-smb", "dst-loop", "owner-c", "owner-b", "owner-a"} {
			e.leaveSession(sk)
		}
	})

	mustUpsert := func(r rt.Route) {
		t.Helper()
		if err := e.UpsertRoute(r); err != nil {
			t.Fatalf("upsert peer %d (%s): %v", r.PeerID, r.User, err)
		}
	}
	mustForwardNoLoop := func(pkt []byte, ingress rt.SessionKey) {
		t.Helper()
		d := e.handleIngressSession(pkt, ingress)
		if d.Action != rt.ActionForward || d.EgressSession == ingress {
			t.Fatalf("expected non-loop forward for %s, got %+v", ingress, d)
		}
		e.forwardPackets.Add(1)
	}
	mustDrop := func(pkt []byte, ingress rt.SessionKey) {
		t.Helper()
		if d := e.handleIngressSession(pkt, ingress); d.Action != rt.ActionDrop {
			t.Fatalf("expected drop for %s, got %+v", ingress, d)
		}
		e.dropPackets.Add(1)
	}

	mustUpsert(rt.Route{PeerID: 800, User: "owner-a", FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.235.0.0/24")}, FilterDestinationIPs: []netip.Prefix{netip.MustParsePrefix("10.235.9.0/24")}, AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.235.0.0/24")}})
	mustUpsert(rt.Route{PeerID: 801, User: "dst-loop", FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.235.9.0/24")}, AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.235.9.0/24")}})
	mustUpsert(rt.Route{PeerID: 802, User: "dst-smb", FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.235.9.0/24")}, AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.235.9.0/24")}})
	e.setEgressSessionForTesting(802, "dst-smb")

	steps := []struct {
		owner rt.SessionKey
		src   [4]byte
		cidr  string
	}{
		{owner: "owner-a", src: [4]byte{10, 235, 0, 10}, cidr: "10.235.0.0/24"},
		{owner: "owner-b", src: [4]byte{10, 235, 1, 10}, cidr: "10.235.1.0/24"},
		{owner: "owner-c", src: [4]byte{10, 235, 2, 10}, cidr: "10.235.2.0/24"},
	}
	dst := [4]byte{10, 235, 9, 10}
	prevDrop := e.SnapshotMetrics().DropPackets
	for i, s := range steps {
		mustUpsert(rt.Route{
			PeerID:               800,
			User:                 string(s.owner),
			FilterSourceIPs:      []netip.Prefix{netip.MustParsePrefix(s.cidr)},
			FilterDestinationIPs: []netip.Prefix{netip.MustParsePrefix("10.235.9.0/24")},
			AllowedIPs:           []netip.Prefix{netip.MustParsePrefix(s.cidr)},
		})
		e.setEgressSessionForTesting(801, s.owner)
		mustForwardNoLoop(makeIPv4(s.src, dst), s.owner)

		e.RemoveRoute(802)
		mustDrop(makeIPv4(s.src, dst), s.owner)
		curDrop := e.SnapshotMetrics().DropPackets
		if curDrop <= prevDrop {
			t.Fatalf("step %d: dataplane stall window did not increase drop metrics: prev=%d cur=%d", i, prevDrop, curDrop)
		}
		prevDrop = curDrop

		mustUpsert(rt.Route{PeerID: 802, User: "dst-smb", FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.235.9.0/24")}, AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.235.9.0/24")}})
		e.setEgressSessionForTesting(802, "dst-smb")
		mustForwardNoLoop(makeIPv4(s.src, dst), s.owner)
	}

	m := e.SnapshotMetrics()
	if m.ForwardPackets != 6 || m.DropPackets != 3 || m.ControlUpsertOK != 9 || m.ControlRemoveOK != 3 || m.ControlErrors != 0 {
		t.Fatalf("unexpected metrics in dataplane stall/drop growth test: %+v", m)
	}
}

func TestEndpointOwnerStepControlPlaneErrorJitterKeepsNonLoopForwarding(t *testing.T) {
	e := &Endpoint{
		engine:   rt.NewMemEngine(),
		peerUser: map[rt.RouteID]string{},
		userRef:  map[rt.SessionKey]int{},
		sessions: map[rt.SessionKey]N.PacketConn{},
	}
	for _, sk := range []rt.SessionKey{"owner-a", "owner-b", "owner-c", "dst-smb"} {
		e.enterSession(sk)
	}
	t.Cleanup(func() {
		for _, sk := range []rt.SessionKey{"dst-smb", "owner-c", "owner-b", "owner-a"} {
			e.leaveSession(sk)
		}
	})

	mustUpsert := func(r rt.Route) {
		t.Helper()
		if err := e.UpsertRoute(r); err != nil {
			t.Fatalf("upsert peer %d (%s): %v", r.PeerID, r.User, err)
		}
	}
	mustForwardNoLoop := func(pkt []byte, ingress rt.SessionKey) {
		t.Helper()
		d := e.handleIngressSession(pkt, ingress)
		if d.Action != rt.ActionForward || d.EgressSession == ingress {
			t.Fatalf("expected non-loop forward for %s, got %+v", ingress, d)
		}
		e.forwardPackets.Add(1)
	}

	mustUpsert(rt.Route{PeerID: 810, User: "owner-a", FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.236.0.0/24")}, FilterDestinationIPs: []netip.Prefix{netip.MustParsePrefix("10.236.9.0/24")}, AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.236.0.0/24")}})
	mustUpsert(rt.Route{PeerID: 811, User: "dst-smb", FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.236.9.0/24")}, AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.236.9.0/24")}})
	e.setEgressSessionForTesting(811, "dst-smb")

	steps := []struct {
		owner rt.SessionKey
		cidr  string
		src   [4]byte
	}{
		{owner: "owner-a", cidr: "10.236.0.0/24", src: [4]byte{10, 236, 0, 10}},
		{owner: "owner-b", cidr: "10.236.1.0/24", src: [4]byte{10, 236, 1, 10}},
		{owner: "owner-c", cidr: "10.236.2.0/24", src: [4]byte{10, 236, 2, 10}},
	}
	dst := [4]byte{10, 236, 9, 10}

	for _, s := range steps {
		mustUpsert(rt.Route{
			PeerID:               810,
			User:                 string(s.owner),
			FilterSourceIPs:      []netip.Prefix{netip.MustParsePrefix(s.cidr)},
			FilterDestinationIPs: []netip.Prefix{netip.MustParsePrefix("10.236.9.0/24")},
			AllowedIPs:           []netip.Prefix{netip.MustParsePrefix(s.cidr)},
		})
		if err := e.UpsertRoute(rt.Route{
			PeerID:          910 + rt.RouteID(len(s.cidr)),
			User:            "",
			FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.236.0.0/24")},
		}); err == nil {
			t.Fatalf("expected control-plane validation error for empty owner")
		}
		mustForwardNoLoop(makeIPv4(s.src, dst), s.owner)
	}

	m := e.SnapshotMetrics()
	if m.ForwardPackets != 3 || m.DropPackets != 0 || m.ControlUpsertOK != 5 || m.ControlErrors != 3 {
		t.Fatalf("unexpected metrics in control-plane jitter/no-loop test: %+v", m)
	}
}

func TestEndpointOwnerStepControlPlaneJitterLoopOnlyWindowDropThenRecoverNoLoop(t *testing.T) {
	e := &Endpoint{
		engine:   rt.NewMemEngine(),
		peerUser: map[rt.RouteID]string{},
		userRef:  map[rt.SessionKey]int{},
		sessions: map[rt.SessionKey]N.PacketConn{},
	}
	for _, sk := range []rt.SessionKey{"owner-a", "owner-b", "owner-c", "dst-loop", "dst-smb"} {
		e.enterSession(sk)
	}
	t.Cleanup(func() {
		for _, sk := range []rt.SessionKey{"dst-smb", "dst-loop", "owner-c", "owner-b", "owner-a"} {
			e.leaveSession(sk)
		}
	})

	mustUpsert := func(r rt.Route) {
		t.Helper()
		if err := e.UpsertRoute(r); err != nil {
			t.Fatalf("upsert peer %d (%s): %v", r.PeerID, r.User, err)
		}
	}
	mustForwardNoLoop := func(pkt []byte, ingress rt.SessionKey) {
		t.Helper()
		d := e.handleIngressSession(pkt, ingress)
		if d.Action != rt.ActionForward || d.EgressSession == ingress {
			t.Fatalf("expected non-loop forward for %s, got %+v", ingress, d)
		}
		e.forwardPackets.Add(1)
	}
	mustDrop := func(pkt []byte, ingress rt.SessionKey) {
		t.Helper()
		if d := e.handleIngressSession(pkt, ingress); d.Action != rt.ActionDrop {
			t.Fatalf("expected drop for %s, got %+v", ingress, d)
		}
		e.dropPackets.Add(1)
	}

	mustUpsert(rt.Route{PeerID: 820, User: "owner-a", FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.238.0.0/24")}, FilterDestinationIPs: []netip.Prefix{netip.MustParsePrefix("10.238.9.0/24")}, AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.238.0.0/24")}})
	mustUpsert(rt.Route{PeerID: 821, User: "dst-loop", FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.238.9.0/24")}, AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.238.9.0/24")}})
	mustUpsert(rt.Route{PeerID: 822, User: "dst-smb", FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.238.9.0/24")}, AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.238.9.0/24")}})
	e.setEgressSessionForTesting(822, "dst-smb")

	steps := []struct {
		owner      rt.SessionKey
		src        [4]byte
		cidr       string
		loopWindow bool
	}{
		{owner: "owner-a", src: [4]byte{10, 238, 0, 10}, cidr: "10.238.0.0/24"},
		{owner: "owner-b", src: [4]byte{10, 238, 1, 10}, cidr: "10.238.1.0/24", loopWindow: true},
		{owner: "owner-c", src: [4]byte{10, 238, 2, 10}, cidr: "10.238.2.0/24"},
	}
	dst := [4]byte{10, 238, 9, 10}
	for i, s := range steps {
		mustUpsert(rt.Route{
			PeerID:               820,
			User:                 string(s.owner),
			FilterSourceIPs:      []netip.Prefix{netip.MustParsePrefix(s.cidr)},
			FilterDestinationIPs: []netip.Prefix{netip.MustParsePrefix("10.238.9.0/24")},
			AllowedIPs:           []netip.Prefix{netip.MustParsePrefix(s.cidr)},
		})
		e.setEgressSessionForTesting(821, s.owner)

		if err := e.UpsertRoute(rt.Route{
			PeerID:          980 + rt.RouteID(i),
			User:            "",
			FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.238.0.0/24")},
		}); err == nil {
			t.Fatalf("step %d: expected control-plane validation error for empty owner", i)
		}

		if s.loopWindow {
			e.RemoveRoute(822)
			mustDrop(makeIPv4(s.src, dst), s.owner)
			mustUpsert(rt.Route{PeerID: 822, User: "dst-smb", FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.238.9.0/24")}, AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.238.9.0/24")}})
			e.setEgressSessionForTesting(822, "dst-smb")
		}

		mustForwardNoLoop(makeIPv4(s.src, dst), s.owner)
		if i > 0 {
			prev := steps[i-1]
			mustDrop(makeIPv4(prev.src, dst), prev.owner)
		}
	}

	m := e.SnapshotMetrics()
	if m.ForwardPackets != 3 || m.DropPackets != 3 || m.ControlUpsertOK != 7 || m.ControlRemoveOK != 1 || m.ControlErrors != 3 {
		t.Fatalf("unexpected metrics in control-plane jitter loop-window test: %+v", m)
	}
}

func TestEndpointOwnerStepControlPlaneResultBaselineAllVsAnomalyKeepsNoLoop(t *testing.T) {
	e := &Endpoint{
		engine:   rt.NewMemEngine(),
		peerUser: map[rt.RouteID]string{},
		userRef:  map[rt.SessionKey]int{},
		sessions: map[rt.SessionKey]N.PacketConn{},
	}
	for _, sk := range []rt.SessionKey{"owner-a", "owner-b", "owner-c", "dst-loop", "dst-smb"} {
		e.enterSession(sk)
	}
	t.Cleanup(func() {
		for _, sk := range []rt.SessionKey{"dst-smb", "dst-loop", "owner-c", "owner-b", "owner-a"} {
			e.leaveSession(sk)
		}
	})

	mustUpsert := func(r rt.Route) {
		t.Helper()
		if err := e.UpsertRoute(r); err != nil {
			t.Fatalf("upsert peer %d (%s): %v", r.PeerID, r.User, err)
		}
	}
	mustForwardNoLoop := func(pkt []byte, ingress rt.SessionKey) {
		t.Helper()
		d := e.handleIngressSession(pkt, ingress)
		if d.Action != rt.ActionForward || d.EgressSession == ingress {
			t.Fatalf("expected non-loop forward for %s, got %+v", ingress, d)
		}
		e.forwardPackets.Add(1)
	}
	mustDrop := func(pkt []byte, ingress rt.SessionKey) {
		t.Helper()
		if d := e.handleIngressSession(pkt, ingress); d.Action != rt.ActionDrop {
			t.Fatalf("expected drop for %s, got %+v", ingress, d)
		}
		e.dropPackets.Add(1)
	}

	mustUpsert(rt.Route{PeerID: 830, User: "owner-a", FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.239.0.0/24")}, FilterDestinationIPs: []netip.Prefix{netip.MustParsePrefix("10.239.9.0/24")}, AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.239.0.0/24")}})
	mustUpsert(rt.Route{PeerID: 831, User: "dst-loop", FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.239.9.0/24")}, AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.239.9.0/24")}})
	mustUpsert(rt.Route{PeerID: 832, User: "dst-smb", FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.239.9.0/24")}, AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.239.9.0/24")}})
	e.setEgressSessionForTesting(832, "dst-smb")

	steps := []struct {
		owner   rt.SessionKey
		src     [4]byte
		cidr    string
		anomaly bool
	}{
		{owner: "owner-a", src: [4]byte{10, 239, 0, 10}, cidr: "10.239.0.0/24"},
		{owner: "owner-b", src: [4]byte{10, 239, 1, 10}, cidr: "10.239.1.0/24", anomaly: true},
		{owner: "owner-c", src: [4]byte{10, 239, 2, 10}, cidr: "10.239.2.0/24"},
	}
	dst := [4]byte{10, 239, 9, 10}
	for i, s := range steps {
		mustUpsert(rt.Route{
			PeerID:               830,
			User:                 string(s.owner),
			FilterSourceIPs:      []netip.Prefix{netip.MustParsePrefix(s.cidr)},
			FilterDestinationIPs: []netip.Prefix{netip.MustParsePrefix("10.239.9.0/24")},
			AllowedIPs:           []netip.Prefix{netip.MustParsePrefix(s.cidr)},
		})
		e.setEgressSessionForTesting(831, s.owner)

		if s.anomaly {
			e.RemoveRoute(832)
			mustDrop(makeIPv4(s.src, dst), s.owner)
			mustUpsert(rt.Route{PeerID: 832, User: "dst-smb", FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.239.9.0/24")}, AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.239.9.0/24")}})
			e.setEgressSessionForTesting(832, "dst-smb")
		}

		mustForwardNoLoop(makeIPv4(s.src, dst), s.owner)
		if i > 0 {
			prev := steps[i-1]
			mustDrop(makeIPv4(prev.src, dst), prev.owner)
		}
	}

	m := e.SnapshotMetrics()
	if m.ForwardPackets != 3 || m.DropPackets != 3 || m.ControlUpsertOK != 7 || m.ControlRemoveOK != 1 || m.ControlErrors != 0 {
		t.Fatalf("unexpected metrics in control-plane result baseline test: %+v", m)
	}
}

func TestEndpointOwnerStepGuardControlPlaneCrossCheckCompetingPrefixMetrics(t *testing.T) {
	e := &Endpoint{
		engine:   rt.NewMemEngine(),
		peerUser: map[rt.RouteID]string{},
		userRef:  map[rt.SessionKey]int{},
		sessions: map[rt.SessionKey]N.PacketConn{},
	}
	for _, sk := range []rt.SessionKey{"owner-a", "owner-b", "owner-c", "dst-loop", "dst-smb"} {
		e.enterSession(sk)
	}
	t.Cleanup(func() {
		for _, sk := range []rt.SessionKey{"dst-smb", "dst-loop", "owner-c", "owner-b", "owner-a"} {
			e.leaveSession(sk)
		}
	})

	mustUpsert := func(r rt.Route) {
		t.Helper()
		if err := e.UpsertRoute(r); err != nil {
			t.Fatalf("upsert peer %d (%s): %v", r.PeerID, r.User, err)
		}
	}
	mustForwardNoLoop := func(pkt []byte, ingress rt.SessionKey) {
		t.Helper()
		d := e.handleIngressSession(pkt, ingress)
		if d.Action != rt.ActionForward || d.EgressSession == ingress {
			t.Fatalf("expected non-loop forward for %s, got %+v", ingress, d)
		}
		e.forwardPackets.Add(1)
	}
	mustDrop := func(pkt []byte, ingress rt.SessionKey) {
		t.Helper()
		if d := e.handleIngressSession(pkt, ingress); d.Action != rt.ActionDrop {
			t.Fatalf("expected drop for %s, got %+v", ingress, d)
		}
		e.dropPackets.Add(1)
	}

	mustUpsert(rt.Route{PeerID: 840, User: "owner-a", FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.242.0.0/24")}, FilterDestinationIPs: []netip.Prefix{netip.MustParsePrefix("10.242.9.0/24")}, AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.242.0.0/24")}})
	mustUpsert(rt.Route{PeerID: 841, User: "dst-loop", FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.242.9.0/24")}, AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.242.9.0/24")}})
	mustUpsert(rt.Route{PeerID: 842, User: "dst-smb", FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.242.9.0/24")}, AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.242.9.0/24")}})
	e.setEgressSessionForTesting(842, "dst-smb")

	steps := []struct {
		owner      rt.SessionKey
		src        [4]byte
		cidr       string
		loopWindow bool
	}{
		{owner: "owner-a", src: [4]byte{10, 242, 0, 10}, cidr: "10.242.0.0/24"},
		{owner: "owner-b", src: [4]byte{10, 242, 1, 10}, cidr: "10.242.1.0/24", loopWindow: true},
		{owner: "owner-c", src: [4]byte{10, 242, 2, 10}, cidr: "10.242.2.0/24"},
	}
	dst := [4]byte{10, 242, 9, 10}
	for i, s := range steps {
		mustUpsert(rt.Route{
			PeerID:               840,
			User:                 string(s.owner),
			FilterSourceIPs:      []netip.Prefix{netip.MustParsePrefix(s.cidr)},
			FilterDestinationIPs: []netip.Prefix{netip.MustParsePrefix("10.242.9.0/24")},
			AllowedIPs:           []netip.Prefix{netip.MustParsePrefix(s.cidr)},
		})
		e.setEgressSessionForTesting(841, s.owner)

		if s.loopWindow {
			if err := e.UpsertRoute(rt.Route{PeerID: 990 + rt.RouteID(i), User: "", FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.242.0.0/24")}}); err == nil {
				t.Fatalf("step %d: expected control-plane validation error for empty owner", i)
			}
			e.RemoveRoute(842)
			mustDrop(makeIPv4(s.src, dst), s.owner)
			mustUpsert(rt.Route{PeerID: 842, User: "dst-smb", FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.242.9.0/24")}, AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.242.9.0/24")}})
			e.setEgressSessionForTesting(842, "dst-smb")
		}

		mustForwardNoLoop(makeIPv4(s.src, dst), s.owner)
		if i > 0 {
			prev := steps[i-1]
			mustDrop(makeIPv4(prev.src, dst), prev.owner)
		}
	}

	m := e.SnapshotMetrics()
	if m.ForwardPackets != 3 || m.DropPackets != 3 || m.ControlUpsertOK != 7 || m.ControlRemoveOK != 1 || m.ControlErrors != 1 {
		t.Fatalf("unexpected metrics in guard/control-plane cross-check test: %+v", m)
	}
}

func TestEndpointOwnerStepGuardControlPlanePerResultBaselineMetrics(t *testing.T) {
	e := &Endpoint{
		engine:   rt.NewMemEngine(),
		peerUser: map[rt.RouteID]string{},
		userRef:  map[rt.SessionKey]int{},
		sessions: map[rt.SessionKey]N.PacketConn{},
	}
	for _, sk := range []rt.SessionKey{"owner-a", "owner-b", "owner-c", "dst-loop", "dst-smb"} {
		e.enterSession(sk)
	}
	t.Cleanup(func() {
		for _, sk := range []rt.SessionKey{"dst-smb", "dst-loop", "owner-c", "owner-b", "owner-a"} {
			e.leaveSession(sk)
		}
	})

	mustUpsert := func(r rt.Route) {
		t.Helper()
		if err := e.UpsertRoute(r); err != nil {
			t.Fatalf("upsert peer %d (%s): %v", r.PeerID, r.User, err)
		}
	}
	mustForwardNoLoop := func(pkt []byte, ingress rt.SessionKey) {
		t.Helper()
		d := e.handleIngressSession(pkt, ingress)
		if d.Action != rt.ActionForward || d.EgressSession == ingress {
			t.Fatalf("expected non-loop forward for %s, got %+v", ingress, d)
		}
		e.forwardPackets.Add(1)
	}
	mustDrop := func(pkt []byte, ingress rt.SessionKey) {
		t.Helper()
		if d := e.handleIngressSession(pkt, ingress); d.Action != rt.ActionDrop {
			t.Fatalf("expected drop for %s, got %+v", ingress, d)
		}
		e.dropPackets.Add(1)
	}

	mustUpsert(rt.Route{PeerID: 850, User: "owner-a", FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.244.0.0/24")}, FilterDestinationIPs: []netip.Prefix{netip.MustParsePrefix("10.244.9.0/24")}, AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.244.0.0/24")}})
	mustUpsert(rt.Route{PeerID: 851, User: "dst-loop", FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.244.9.0/24")}, AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.244.9.0/24")}})
	mustUpsert(rt.Route{PeerID: 852, User: "dst-smb", FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.244.9.0/24")}, AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.244.9.0/24")}})
	e.setEgressSessionForTesting(852, "dst-smb")

	steps := []struct {
		owner      rt.SessionKey
		src        [4]byte
		cidr       string
		loopWindow bool
	}{
		{owner: "owner-a", src: [4]byte{10, 244, 0, 10}, cidr: "10.244.0.0/24"},
		{owner: "owner-b", src: [4]byte{10, 244, 1, 10}, cidr: "10.244.1.0/24", loopWindow: true},
		{owner: "owner-c", src: [4]byte{10, 244, 2, 10}, cidr: "10.244.2.0/24"},
	}
	dst := [4]byte{10, 244, 9, 10}
	for i, s := range steps {
		mustUpsert(rt.Route{
			PeerID:               850,
			User:                 string(s.owner),
			FilterSourceIPs:      []netip.Prefix{netip.MustParsePrefix(s.cidr)},
			FilterDestinationIPs: []netip.Prefix{netip.MustParsePrefix("10.244.9.0/24")},
			AllowedIPs:           []netip.Prefix{netip.MustParsePrefix(s.cidr)},
		})
		e.setEgressSessionForTesting(851, s.owner)

		if s.loopWindow {
			if err := e.UpsertRoute(rt.Route{PeerID: 995, User: "", FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.244.1.0/24")}}); err == nil {
				t.Fatalf("step %d: expected control-plane validation error for empty owner", i)
			}
			e.RemoveRoute(852)
			mustDrop(makeIPv4(s.src, dst), s.owner)
			mustUpsert(rt.Route{PeerID: 852, User: "dst-smb", FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.244.9.0/24")}, AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.244.9.0/24")}})
			e.setEgressSessionForTesting(852, "dst-smb")
		}

		mustForwardNoLoop(makeIPv4(s.src, dst), s.owner)
		if i > 0 {
			prev := steps[i-1]
			mustDrop(makeIPv4(prev.src, dst), prev.owner)
		}
	}

	m := e.SnapshotMetrics()
	if m.ForwardPackets != 3 || m.DropPackets != 3 || m.ControlUpsertOK != 7 || m.ControlRemoveOK != 1 || m.ControlErrors != 1 {
		t.Fatalf("unexpected metrics in per-result baseline test: %+v", m)
	}
}

func TestEndpointOwnerStepGuardControlPlaneTrendBaselineMetrics(t *testing.T) {
	e := &Endpoint{
		engine:   rt.NewMemEngine(),
		peerUser: map[rt.RouteID]string{},
		userRef:  map[rt.SessionKey]int{},
		sessions: map[rt.SessionKey]N.PacketConn{},
	}
	for _, sk := range []rt.SessionKey{"owner-a", "owner-b", "owner-c", "dst-loop", "dst-smb"} {
		e.enterSession(sk)
	}
	t.Cleanup(func() {
		for _, sk := range []rt.SessionKey{"dst-smb", "dst-loop", "owner-c", "owner-b", "owner-a"} {
			e.leaveSession(sk)
		}
	})

	mustUpsert := func(r rt.Route) {
		t.Helper()
		if err := e.UpsertRoute(r); err != nil {
			t.Fatalf("upsert peer %d (%s): %v", r.PeerID, r.User, err)
		}
	}

	mustUpsert(rt.Route{PeerID: 860, User: "owner-a", FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.246.0.0/24")}, FilterDestinationIPs: []netip.Prefix{netip.MustParsePrefix("10.246.9.0/24")}, AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.246.0.0/24")}})
	mustUpsert(rt.Route{PeerID: 861, User: "dst-loop", FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.246.9.0/24")}, AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.246.9.0/24")}})
	mustUpsert(rt.Route{PeerID: 862, User: "dst-smb", FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.246.9.0/24")}, AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.246.9.0/24")}})
	e.setEgressSessionForTesting(862, "dst-smb")

	steps := []struct {
		owner  rt.SessionKey
		src    [4]byte
		cidr   string
		stall  bool
		jitter bool
	}{
		{owner: "owner-a", src: [4]byte{10, 246, 0, 10}, cidr: "10.246.0.0/24"},
		{owner: "owner-b", src: [4]byte{10, 246, 1, 10}, cidr: "10.246.1.0/24", stall: true, jitter: true},
		{owner: "owner-c", src: [4]byte{10, 246, 2, 10}, cidr: "10.246.2.0/24"},
		{owner: "owner-a", src: [4]byte{10, 246, 3, 10}, cidr: "10.246.3.0/24"},
		{owner: "owner-b", src: [4]byte{10, 246, 4, 10}, cidr: "10.246.4.0/24", stall: true},
		{owner: "owner-c", src: [4]byte{10, 246, 5, 10}, cidr: "10.246.5.0/24"},
	}
	dst := [4]byte{10, 246, 9, 10}

	allSteps := 0
	anomalySteps := 0
	allStallWithoutDrop := 0
	anomalyStallWithoutDrop := 0
	lastDrop := uint64(0)

	for i, s := range steps {
		mustUpsert(rt.Route{
			PeerID:               860,
			User:                 string(s.owner),
			FilterSourceIPs:      []netip.Prefix{netip.MustParsePrefix(s.cidr)},
			FilterDestinationIPs: []netip.Prefix{netip.MustParsePrefix("10.246.9.0/24")},
			AllowedIPs:           []netip.Prefix{netip.MustParsePrefix(s.cidr)},
		})
		e.setEgressSessionForTesting(861, s.owner)

		allSteps++
		dropBefore := e.dropPackets.Load()
		if s.stall {
			anomalySteps++
			if s.jitter {
				if err := e.UpsertRoute(rt.Route{PeerID: 998, User: "", FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.246.1.0/24")}}); err == nil {
					t.Fatalf("step %d: expected control-plane jitter (validation error)", i)
				}
			}
			e.RemoveRoute(862)
			if d := e.handleIngressSession(makeIPv4(s.src, dst), s.owner); d.Action != rt.ActionDrop {
				t.Fatalf("step %d: expected drop in stall window, got %+v", i, d)
			}
			e.dropPackets.Add(1)
			mustUpsert(rt.Route{PeerID: 862, User: "dst-smb", FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.246.9.0/24")}, AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.246.9.0/24")}})
			e.setEgressSessionForTesting(862, "dst-smb")
		}
		dropAfter := e.dropPackets.Load()
		dropDelta := dropAfter - dropBefore
		if s.stall && !s.jitter && dropDelta <= 0 {
			allStallWithoutDrop++
			anomalyStallWithoutDrop++
		}
		lastDrop = dropAfter

		if d := e.handleIngressSession(makeIPv4(s.src, dst), s.owner); d.Action != rt.ActionForward || d.EgressSession == s.owner {
			t.Fatalf("step %d: expected non-loop forward, got %+v", i, d)
		}
		e.forwardPackets.Add(1)
		if i > 0 {
			prev := steps[i-1]
			if d := e.handleIngressSession(makeIPv4(prev.src, dst), prev.owner); d.Action != rt.ActionDrop {
				t.Fatalf("step %d: stale owner %q must drop, got %+v", i, prev.owner, d)
			}
			e.dropPackets.Add(1)
		}
	}

	if allSteps != len(steps) || anomalySteps != 2 {
		t.Fatalf("unexpected trend counters: all=%d anomaly=%d", allSteps, anomalySteps)
	}
	if allStallWithoutDrop != 0 || anomalyStallWithoutDrop != 0 {
		t.Fatalf("unexpected sustained trend shift: all=%d anomaly=%d lastDrop=%d",
			allStallWithoutDrop, anomalyStallWithoutDrop, lastDrop)
	}

	m := e.SnapshotMetrics()
	if m.ForwardPackets != 6 || m.DropPackets < 7 || m.ControlErrors != 1 {
		t.Fatalf("unexpected trend-baseline metrics: %+v", m)
	}
}

func TestEndpointOwnerStepBudgetDecayCooldownWindowTracksNoLoopMetrics(t *testing.T) {
	e := &Endpoint{
		engine:   rt.NewMemEngine(),
		peerUser: map[rt.RouteID]string{},
		userRef:  map[rt.SessionKey]int{},
		sessions: map[rt.SessionKey]N.PacketConn{},
	}
	for _, sk := range []rt.SessionKey{"owner-a", "owner-b", "owner-c", "dst-loop", "dst-smb"} {
		e.enterSession(sk)
	}
	t.Cleanup(func() {
		for _, sk := range []rt.SessionKey{"dst-smb", "dst-loop", "owner-c", "owner-b", "owner-a"} {
			e.leaveSession(sk)
		}
	})

	mustUpsert := func(r rt.Route) {
		t.Helper()
		if err := e.UpsertRoute(r); err != nil {
			t.Fatalf("upsert peer %d (%s): %v", r.PeerID, r.User, err)
		}
	}
	mustUpsert(rt.Route{PeerID: 970, User: "owner-a", FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.251.0.0/24")}, FilterDestinationIPs: []netip.Prefix{netip.MustParsePrefix("10.251.9.0/24")}, AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.251.0.0/24")}})
	mustUpsert(rt.Route{PeerID: 971, User: "dst-loop", FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.251.9.0/24")}, AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.251.9.0/24")}})
	mustUpsert(rt.Route{PeerID: 972, User: "dst-smb", FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.251.9.0/24")}, AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.251.9.0/24")}})
	e.setEgressSessionForTesting(972, "dst-smb")

	steps := []struct {
		owner      rt.SessionKey
		src        [4]byte
		cidr       string
		loopWindow bool
	}{
		{owner: "owner-a", src: [4]byte{10, 251, 0, 10}, cidr: "10.251.0.0/24"},
		{owner: "owner-b", src: [4]byte{10, 251, 1, 10}, cidr: "10.251.1.0/24", loopWindow: true}, // aged anomaly candidate
		{owner: "owner-c", src: [4]byte{10, 251, 2, 10}, cidr: "10.251.2.0/24"},
		{owner: "owner-a", src: [4]byte{10, 251, 3, 10}, cidr: "10.251.3.0/24"},
	}
	dst := [4]byte{10, 251, 9, 10}
	for i, s := range steps {
		mustUpsert(rt.Route{
			PeerID:               970,
			User:                 string(s.owner),
			FilterSourceIPs:      []netip.Prefix{netip.MustParsePrefix(s.cidr)},
			FilterDestinationIPs: []netip.Prefix{netip.MustParsePrefix("10.251.9.0/24")},
			AllowedIPs:           []netip.Prefix{netip.MustParsePrefix(s.cidr)},
		})
		e.setEgressSessionForTesting(971, s.owner)

		if s.loopWindow {
			e.RemoveRoute(972)
			if d := e.handleIngressSession(makeIPv4(s.src, dst), s.owner); d.Action != rt.ActionDrop {
				t.Fatalf("step %d: expected drop in loop-only window, got %+v", i, d)
			}
			e.dropPackets.Add(1)
			mustUpsert(rt.Route{PeerID: 972, User: "dst-smb", FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.251.9.0/24")}, AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.251.9.0/24")}})
			e.setEgressSessionForTesting(972, "dst-smb")
		}

		if d := e.handleIngressSession(makeIPv4(s.src, dst), s.owner); d.Action != rt.ActionForward || d.EgressSession == s.owner {
			t.Fatalf("step %d: expected non-loop forward, got %+v", i, d)
		}
		e.forwardPackets.Add(1)
		if i > 0 {
			prev := steps[i-1]
			if d := e.handleIngressSession(makeIPv4(prev.src, dst), prev.owner); d.Action != rt.ActionDrop {
				t.Fatalf("step %d: stale owner %q must drop, got %+v", i, prev.owner, d)
			}
			e.dropPackets.Add(1)
		}
	}

	m := e.SnapshotMetrics()
	if m.ForwardPackets != uint64(len(steps)) || m.DropPackets < 4 || m.ControlErrors != 0 {
		t.Fatalf("unexpected metrics in decay/cooldown window test: %+v", m)
	}
}

func TestEndpointBidirectionalSMBAuthSymptomOwnerFlapTracksNoLoopMetrics(t *testing.T) {
	e := &Endpoint{
		engine:   rt.NewMemEngine(),
		peerUser: map[rt.RouteID]string{},
		userRef:  map[rt.SessionKey]int{},
		sessions: map[rt.SessionKey]N.PacketConn{},
	}
	for _, owner := range []string{"owner-a", "owner-b", "owner-c", "dst-smb"} {
		e.enterSession(rt.SessionKey(owner))
	}
	t.Cleanup(func() {
		for _, owner := range []string{"dst-smb", "owner-c", "owner-b", "owner-a"} {
			e.leaveSession(rt.SessionKey(owner))
		}
	})
	mustUpsert := func(route rt.Route) {
		if err := e.UpsertRoute(route); err != nil {
			t.Fatalf("upsert peer %d: %v", route.PeerID, err)
		}
	}
	mustUpsert(rt.Route{PeerID: 983, User: "owner-a", FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.253.0.0/24")}, AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.253.0.0/24")}})
	mustUpsert(rt.Route{PeerID: 984, User: "dst-smb", FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.253.9.0/24")}, AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.253.9.0/24")}})
	mustUpsert(rt.Route{PeerID: 985, User: "owner-a", AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.253.9.0/24")}})
	e.setEgressSessionForTesting(984, "dst-smb")

	steps := []struct {
		owner string
		src   [4]byte
		cidr  string
	}{
		{owner: "owner-a", src: [4]byte{10, 253, 0, 10}, cidr: "10.253.0.0/24"},
		{owner: "owner-b", src: [4]byte{10, 253, 1, 10}, cidr: "10.253.1.0/24"},
		{owner: "owner-c", src: [4]byte{10, 253, 2, 10}, cidr: "10.253.2.0/24"},
	}
	dst := [4]byte{10, 253, 9, 44}
	for i, s := range steps {
		mustUpsert(rt.Route{
			PeerID:               983,
			User:                 s.owner,
			FilterSourceIPs:      []netip.Prefix{netip.MustParsePrefix(s.cidr)},
			FilterDestinationIPs: []netip.Prefix{netip.MustParsePrefix("10.253.9.0/24")},
			AllowedIPs:           []netip.Prefix{netip.MustParsePrefix(s.cidr)},
		})
		e.setEgressSessionForTesting(985, rt.SessionKey(s.owner)) // force loop candidate
		d := e.handleIngressSession(makeIPv4(s.src, dst), rt.SessionKey(s.owner))
		if d.Action != rt.ActionForward || d.EgressSession != "dst-smb" {
			t.Fatalf("step %d: expected non-loop forward to dst-smb, got %+v", i, d)
		}
		e.forwardPackets.Add(1)
		if i > 0 {
			prev := steps[i-1]
			if d := e.handleIngressSession(makeIPv4(prev.src, dst), rt.SessionKey(prev.owner)); d.Action != rt.ActionDrop {
				t.Fatalf("step %d: stale owner %q must drop, got %+v", i, prev.owner, d)
			}
			e.dropPackets.Add(1)
		}
	}

	m := e.SnapshotMetrics()
	if m.ForwardPackets != uint64(len(steps)) || m.DropPackets != uint64(len(steps)-1) || m.ControlErrors != 0 {
		t.Fatalf("unexpected metrics in bidirectional auth symptom guard test: %+v", m)
	}
}

func TestEndpointOwnerStepNoisySuppressionDecisionWindowTracksNoLoopMetrics(t *testing.T) {
	e := &Endpoint{
		engine:   rt.NewMemEngine(),
		peerUser: map[rt.RouteID]string{},
		userRef:  map[rt.SessionKey]int{},
		sessions: map[rt.SessionKey]N.PacketConn{},
	}
	for _, owner := range []rt.SessionKey{"owner-a", "owner-b", "owner-c", "dst-smb"} {
		e.enterSession(owner)
	}
	t.Cleanup(func() {
		for _, owner := range []rt.SessionKey{"dst-smb", "owner-c", "owner-b", "owner-a"} {
			e.leaveSession(owner)
		}
	})

	mustUpsert := func(route rt.Route) {
		t.Helper()
		if err := e.UpsertRoute(route); err != nil {
			t.Fatalf("upsert peer %d(%s): %v", route.PeerID, route.User, err)
		}
	}
	mustUpsert(rt.Route{
		PeerID:               1101,
		User:                 "owner-a",
		FilterSourceIPs:      []netip.Prefix{netip.MustParsePrefix("10.255.0.0/24")},
		FilterDestinationIPs: []netip.Prefix{netip.MustParsePrefix("10.255.9.0/24")},
		AllowedIPs:           []netip.Prefix{netip.MustParsePrefix("10.255.0.0/24")},
	})
	mustUpsert(rt.Route{
		PeerID:     1102,
		User:       "owner-a",
		AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.255.9.0/24")},
	})
	mustUpsert(rt.Route{
		PeerID:          1103,
		User:            "dst-smb",
		FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.255.9.0/24")},
		AllowedIPs:      []netip.Prefix{netip.MustParsePrefix("10.255.9.0/24")},
	})
	e.setEgressSessionForTesting(1103, "dst-smb")

	steps := []struct {
		owner      string
		src        [4]byte
		cidr       string
		loopWindow bool
	}{
		{owner: "owner-a", src: [4]byte{10, 255, 0, 10}, cidr: "10.255.0.0/24"},
		{owner: "owner-b", src: [4]byte{10, 255, 1, 10}, cidr: "10.255.1.0/24", loopWindow: true},
		{owner: "owner-c", src: [4]byte{10, 255, 2, 10}, cidr: "10.255.2.0/24"},
		{owner: "owner-b", src: [4]byte{10, 255, 3, 10}, cidr: "10.255.3.0/24"},
	}
	dst := [4]byte{10, 255, 9, 44}

	for i, s := range steps {
		mustUpsert(rt.Route{
			PeerID:               1101,
			User:                 s.owner,
			FilterSourceIPs:      []netip.Prefix{netip.MustParsePrefix(s.cidr)},
			FilterDestinationIPs: []netip.Prefix{netip.MustParsePrefix("10.255.9.0/24")},
			AllowedIPs:           []netip.Prefix{netip.MustParsePrefix(s.cidr)},
		})
		e.setEgressSessionForTesting(1102, rt.SessionKey(s.owner))
		if s.loopWindow {
			e.RemoveRoute(1103)
			if d := e.handleIngressSession(makeIPv4(s.src, dst), rt.SessionKey(s.owner)); d.Action != rt.ActionDrop {
				t.Fatalf("step %d: expected drop in loop-only window, got %+v", i, d)
			}
			e.dropPackets.Add(1)
			mustUpsert(rt.Route{
				PeerID:          1103,
				User:            "dst-smb",
				FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.255.9.0/24")},
				AllowedIPs:      []netip.Prefix{netip.MustParsePrefix("10.255.9.0/24")},
			})
			e.setEgressSessionForTesting(1103, "dst-smb")
		}
		d := e.handleIngressSession(makeIPv4(s.src, dst), rt.SessionKey(s.owner))
		if d.Action != rt.ActionForward || d.EgressSession != "dst-smb" {
			t.Fatalf("step %d: expected non-loop SMB forward, got %+v", i, d)
		}
		e.forwardPackets.Add(1)
		if i > 0 {
			prev := steps[i-1]
			if d := e.handleIngressSession(makeIPv4(prev.src, dst), rt.SessionKey(prev.owner)); d.Action != rt.ActionDrop {
				t.Fatalf("step %d: stale owner %q must drop, got %+v", i, prev.owner, d)
			}
			e.dropPackets.Add(1)
		}
	}

	m := e.SnapshotMetrics()
	if m.ForwardPackets != uint64(len(steps)) || m.DropPackets < 4 || m.ControlErrors != 0 {
		t.Fatalf("unexpected metrics in noisy suppression decision window test: %+v", m)
	}
}

func TestEndpointOwnerStepAgeWeightedSuppressionWindowTracksNoLoopAndStaleDrop(t *testing.T) {
	e := &Endpoint{
		engine:   rt.NewMemEngine(),
		peerUser: map[rt.RouteID]string{},
		userRef:  map[rt.SessionKey]int{},
		sessions: map[rt.SessionKey]N.PacketConn{},
	}
	for _, owner := range []rt.SessionKey{"owner-a", "owner-b", "owner-c", "dst-smb"} {
		e.enterSession(owner)
	}
	t.Cleanup(func() {
		for _, owner := range []rt.SessionKey{"dst-smb", "owner-c", "owner-b", "owner-a"} {
			e.leaveSession(owner)
		}
	})
	mustUpsert := func(route rt.Route) {
		t.Helper()
		if err := e.UpsertRoute(route); err != nil {
			t.Fatalf("upsert peer %d(%s): %v", route.PeerID, route.User, err)
		}
	}
	mustUpsert(rt.Route{
		PeerID:               1201,
		User:                 "owner-a",
		FilterSourceIPs:      []netip.Prefix{netip.MustParsePrefix("10.249.0.0/24")},
		FilterDestinationIPs: []netip.Prefix{netip.MustParsePrefix("10.249.9.0/24")},
		AllowedIPs:           []netip.Prefix{netip.MustParsePrefix("10.249.0.0/24")},
	})
	mustUpsert(rt.Route{
		PeerID:     1202,
		User:       "owner-a",
		AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.249.9.0/24")},
	})
	mustUpsert(rt.Route{
		PeerID:          1203,
		User:            "dst-smb",
		FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.249.9.0/24")},
		AllowedIPs:      []netip.Prefix{netip.MustParsePrefix("10.249.9.0/24")},
	})
	e.setEgressSessionForTesting(1203, "dst-smb")

	steps := []struct {
		owner string
		src   [4]byte
		cidr  string
	}{
		{owner: "owner-a", src: [4]byte{10, 249, 0, 10}, cidr: "10.249.0.0/24"},
		{owner: "owner-b", src: [4]byte{10, 249, 1, 10}, cidr: "10.249.1.0/24"},
		{owner: "owner-a", src: [4]byte{10, 249, 2, 10}, cidr: "10.249.2.0/24"},
		{owner: "owner-c", src: [4]byte{10, 249, 3, 10}, cidr: "10.249.3.0/24"},
		{owner: "owner-c", src: [4]byte{10, 249, 4, 10}, cidr: "10.249.4.0/24"},
	}
	dst := [4]byte{10, 249, 9, 44}

	for i, s := range steps {
		mustUpsert(rt.Route{
			PeerID:               1201,
			User:                 s.owner,
			FilterSourceIPs:      []netip.Prefix{netip.MustParsePrefix(s.cidr)},
			FilterDestinationIPs: []netip.Prefix{netip.MustParsePrefix("10.249.9.0/24")},
			AllowedIPs:           []netip.Prefix{netip.MustParsePrefix(s.cidr)},
		})
		e.setEgressSessionForTesting(1202, rt.SessionKey(s.owner))
		d := e.handleIngressSession(makeIPv4(s.src, dst), rt.SessionKey(s.owner))
		if d.Action != rt.ActionForward || d.EgressSession != "dst-smb" {
			t.Fatalf("step %d: expected non-loop SMB forward, got %+v", i, d)
		}
		e.forwardPackets.Add(1)
		if i > 0 {
			prev := steps[i-1]
			if d := e.handleIngressSession(makeIPv4(prev.src, dst), rt.SessionKey(prev.owner)); d.Action != rt.ActionDrop {
				t.Fatalf("step %d: stale owner %q must drop, got %+v", i, prev.owner, d)
			}
			e.dropPackets.Add(1)
		}
	}

	m := e.SnapshotMetrics()
	if m.ForwardPackets != uint64(len(steps)) || m.DropPackets != uint64(len(steps)-1) || m.ControlErrors != 0 {
		t.Fatalf("unexpected metrics in age-weighted suppression window test: %+v", m)
	}
}

func TestEndpointOwnerStepTrendAgeStabilityLoopOnlyWindowTracksDropAndRecovery(t *testing.T) {
	e := &Endpoint{
		engine:   rt.NewMemEngine(),
		peerUser: map[rt.RouteID]string{},
		userRef:  map[rt.SessionKey]int{},
		sessions: map[rt.SessionKey]N.PacketConn{},
	}
	for _, owner := range []rt.SessionKey{"owner-a", "owner-b", "owner-c", "dst-smb"} {
		e.enterSession(owner)
	}
	t.Cleanup(func() {
		for _, owner := range []rt.SessionKey{"dst-smb", "owner-c", "owner-b", "owner-a"} {
			e.leaveSession(owner)
		}
	})
	mustUpsert := func(route rt.Route) {
		t.Helper()
		if err := e.UpsertRoute(route); err != nil {
			t.Fatalf("upsert peer %d(%s): %v", route.PeerID, route.User, err)
		}
	}
	mustUpsert(rt.Route{
		PeerID:               1301,
		User:                 "owner-a",
		FilterSourceIPs:      []netip.Prefix{netip.MustParsePrefix("10.248.0.0/24")},
		FilterDestinationIPs: []netip.Prefix{netip.MustParsePrefix("10.248.9.0/24")},
		AllowedIPs:           []netip.Prefix{netip.MustParsePrefix("10.248.0.0/24")},
	})
	mustUpsert(rt.Route{PeerID: 1302, User: "owner-a", AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.248.9.0/24")}})
	mustUpsert(rt.Route{
		PeerID:          1303,
		User:            "dst-smb",
		FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.248.9.0/24")},
		AllowedIPs:      []netip.Prefix{netip.MustParsePrefix("10.248.9.0/24")},
	})
	e.setEgressSessionForTesting(1303, "dst-smb")

	steps := []struct {
		owner      string
		src        [4]byte
		cidr       string
		loopWindow bool
	}{
		{owner: "owner-a", src: [4]byte{10, 248, 0, 10}, cidr: "10.248.0.0/24"},
		{owner: "owner-b", src: [4]byte{10, 248, 1, 10}, cidr: "10.248.1.0/24", loopWindow: true},
		{owner: "owner-c", src: [4]byte{10, 248, 2, 10}, cidr: "10.248.2.0/24"},
	}
	dst := [4]byte{10, 248, 9, 44}

	for i, s := range steps {
		mustUpsert(rt.Route{
			PeerID:               1301,
			User:                 s.owner,
			FilterSourceIPs:      []netip.Prefix{netip.MustParsePrefix(s.cidr)},
			FilterDestinationIPs: []netip.Prefix{netip.MustParsePrefix("10.248.9.0/24")},
			AllowedIPs:           []netip.Prefix{netip.MustParsePrefix(s.cidr)},
		})
		e.setEgressSessionForTesting(1302, rt.SessionKey(s.owner))
		if s.loopWindow {
			e.RemoveRoute(1303)
			if d := e.handleIngressSession(makeIPv4(s.src, dst), rt.SessionKey(s.owner)); d.Action != rt.ActionDrop {
				t.Fatalf("step %d: expected drop in loop-only window, got %+v", i, d)
			}
			e.dropPackets.Add(1)
			mustUpsert(rt.Route{
				PeerID:          1303,
				User:            "dst-smb",
				FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.248.9.0/24")},
				AllowedIPs:      []netip.Prefix{netip.MustParsePrefix("10.248.9.0/24")},
			})
			e.setEgressSessionForTesting(1303, "dst-smb")
		}
		d := e.handleIngressSession(makeIPv4(s.src, dst), rt.SessionKey(s.owner))
		if d.Action != rt.ActionForward || d.EgressSession != "dst-smb" {
			t.Fatalf("step %d: expected recovered non-loop forwarding, got %+v", i, d)
		}
		e.forwardPackets.Add(1)
		if i > 0 {
			prev := steps[i-1]
			if d := e.handleIngressSession(makeIPv4(prev.src, dst), rt.SessionKey(prev.owner)); d.Action != rt.ActionDrop {
				t.Fatalf("step %d: stale owner %q must drop, got %+v", i, prev.owner, d)
			}
			e.dropPackets.Add(1)
		}
	}

	m := e.SnapshotMetrics()
	if m.ForwardPackets != uint64(len(steps)) || m.DropPackets < uint64(len(steps)) || m.ControlErrors != 0 {
		t.Fatalf("unexpected metrics in trend-age stability loop-only test: %+v", m)
	}
}

func TestEndpointOwnerStepAuthSymptomCompetingRouteChurnLoopWindowTracksMetrics(t *testing.T) {
	e := &Endpoint{
		engine:   rt.NewMemEngine(),
		peerUser: map[rt.RouteID]string{},
		userRef:  map[rt.SessionKey]int{},
		sessions: map[rt.SessionKey]N.PacketConn{},
	}
	for _, owner := range []rt.SessionKey{"owner-a", "owner-b", "owner-c", "dst-a", "dst-b"} {
		e.enterSession(owner)
	}
	t.Cleanup(func() {
		for _, owner := range []rt.SessionKey{"dst-b", "dst-a", "owner-c", "owner-b", "owner-a"} {
			e.leaveSession(owner)
		}
	})
	mustUpsert := func(route rt.Route) {
		t.Helper()
		if err := e.UpsertRoute(route); err != nil {
			t.Fatalf("upsert peer %d(%s): %v", route.PeerID, route.User, err)
		}
	}

	mustUpsert(rt.Route{
		PeerID:               1401,
		User:                 "owner-a",
		FilterSourceIPs:      []netip.Prefix{netip.MustParsePrefix("10.246.0.0/24")},
		FilterDestinationIPs: []netip.Prefix{netip.MustParsePrefix("10.246.9.0/24")},
		AllowedIPs:           []netip.Prefix{netip.MustParsePrefix("10.246.0.0/24")},
	})
	mustUpsert(rt.Route{PeerID: 1402, User: "owner-a", AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.246.9.0/24")}})
	mustUpsert(rt.Route{PeerID: 1403, User: "dst-a", AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.246.9.0/24")}})
	mustUpsert(rt.Route{PeerID: 1404, User: "dst-b", AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.246.9.0/24")}})
	e.setEgressSessionForTesting(1403, "dst-a")
	e.setEgressSessionForTesting(1404, "dst-b")

	steps := []struct {
		owner      string
		src        [4]byte
		cidr       string
		withdrawA  bool
		withdrawB  bool
		expectDest rt.SessionKey
	}{
		{owner: "owner-a", src: [4]byte{10, 246, 0, 10}, cidr: "10.246.0.0/24", expectDest: "dst-a"},
		{owner: "owner-b", src: [4]byte{10, 246, 1, 10}, cidr: "10.246.1.0/24", withdrawA: true, expectDest: "dst-b"},
		{owner: "owner-c", src: [4]byte{10, 246, 2, 10}, cidr: "10.246.2.0/24", withdrawA: true, withdrawB: true},
		{owner: "owner-b", src: [4]byte{10, 246, 3, 10}, cidr: "10.246.3.0/24", expectDest: "dst-a"},
	}
	dst := [4]byte{10, 246, 9, 44}

	for i, s := range steps {
		mustUpsert(rt.Route{
			PeerID:               1401,
			User:                 s.owner,
			FilterSourceIPs:      []netip.Prefix{netip.MustParsePrefix(s.cidr)},
			FilterDestinationIPs: []netip.Prefix{netip.MustParsePrefix("10.246.9.0/24")},
			AllowedIPs:           []netip.Prefix{netip.MustParsePrefix(s.cidr)},
		})
		e.setEgressSessionForTesting(1402, rt.SessionKey(s.owner))

		if s.withdrawA {
			e.RemoveRoute(1403)
		} else {
			mustUpsert(rt.Route{PeerID: 1403, User: "dst-a", AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.246.9.0/24")}})
			e.setEgressSessionForTesting(1403, "dst-a")
		}
		if s.withdrawB {
			e.RemoveRoute(1404)
		} else {
			mustUpsert(rt.Route{PeerID: 1404, User: "dst-b", AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.246.9.0/24")}})
			e.setEgressSessionForTesting(1404, "dst-b")
		}

		d := e.handleIngressSession(makeIPv4(s.src, dst), rt.SessionKey(s.owner))
		if s.expectDest == "" {
			if d.Action != rt.ActionDrop {
				t.Fatalf("step %d: expected drop in loop-only window, got %+v", i, d)
			}
			e.dropPackets.Add(1)
		} else if d.Action != rt.ActionForward || d.EgressSession != s.expectDest {
			t.Fatalf("step %d: expected non-loop forward to %q, got %+v", i, s.expectDest, d)
		} else {
			e.forwardPackets.Add(1)
		}

		if i > 0 {
			prev := steps[i-1]
			if d := e.handleIngressSession(makeIPv4(prev.src, dst), rt.SessionKey(prev.owner)); d.Action != rt.ActionDrop {
				t.Fatalf("step %d: stale owner %q must drop, got %+v", i, prev.owner, d)
			}
			e.dropPackets.Add(1)
		}
	}

	m := e.SnapshotMetrics()
	if m.ForwardPackets != 3 || m.DropPackets < 4 || m.ControlErrors != 0 {
		t.Fatalf("unexpected metrics in auth-symptom competing churn test: %+v", m)
	}
}

func TestEndpointOwnerStepRecommendationConfidenceBucketChurnKeepsNoLoopMetrics(t *testing.T) {
	e := &Endpoint{
		engine:   rt.NewMemEngine(),
		peerUser: map[rt.RouteID]string{},
		userRef:  map[rt.SessionKey]int{},
		sessions: map[rt.SessionKey]N.PacketConn{},
	}
	for _, owner := range []rt.SessionKey{"owner-a", "owner-b", "owner-c", "dst-smb"} {
		e.enterSession(owner)
	}
	t.Cleanup(func() {
		for _, owner := range []rt.SessionKey{"dst-smb", "owner-c", "owner-b", "owner-a"} {
			e.leaveSession(owner)
		}
	})
	mustUpsert := func(route rt.Route) {
		t.Helper()
		if err := e.UpsertRoute(route); err != nil {
			t.Fatalf("upsert peer %d(%s): %v", route.PeerID, route.User, err)
		}
	}

	mustUpsert(rt.Route{
		PeerID:               1451,
		User:                 "owner-a",
		FilterSourceIPs:      []netip.Prefix{netip.MustParsePrefix("10.244.0.0/24")},
		FilterDestinationIPs: []netip.Prefix{netip.MustParsePrefix("10.244.9.0/24")},
		AllowedIPs:           []netip.Prefix{netip.MustParsePrefix("10.244.0.0/24")},
	})
	mustUpsert(rt.Route{PeerID: 1452, User: "owner-a", AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.244.9.0/24")}})
	mustUpsert(rt.Route{PeerID: 1453, User: "dst-smb", AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.244.9.0/24")}})
	e.setEgressSessionForTesting(1453, "dst-smb")

	steps := []struct {
		owner       string
		src         [4]byte
		cidr        string
		withdrawDst bool
		expectDrop  bool
	}{
		{owner: "owner-a", src: [4]byte{10, 244, 0, 10}, cidr: "10.244.0.0/24"},
		{owner: "owner-b", src: [4]byte{10, 244, 1, 10}, cidr: "10.244.1.0/24"},
		{owner: "owner-c", src: [4]byte{10, 244, 2, 10}, cidr: "10.244.2.0/24", withdrawDst: true, expectDrop: true},
		{owner: "owner-b", src: [4]byte{10, 244, 3, 10}, cidr: "10.244.3.0/24"},
	}
	dst := [4]byte{10, 244, 9, 44}

	for i, s := range steps {
		mustUpsert(rt.Route{
			PeerID:               1451,
			User:                 s.owner,
			FilterSourceIPs:      []netip.Prefix{netip.MustParsePrefix(s.cidr)},
			FilterDestinationIPs: []netip.Prefix{netip.MustParsePrefix("10.244.9.0/24")},
			AllowedIPs:           []netip.Prefix{netip.MustParsePrefix(s.cidr)},
		})
		e.setEgressSessionForTesting(1452, rt.SessionKey(s.owner))
		if s.withdrawDst {
			e.RemoveRoute(1453)
		} else {
			mustUpsert(rt.Route{PeerID: 1453, User: "dst-smb", AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.244.9.0/24")}})
			e.setEgressSessionForTesting(1453, "dst-smb")
		}

		d := e.handleIngressSession(makeIPv4(s.src, dst), rt.SessionKey(s.owner))
		if s.expectDrop {
			if d.Action != rt.ActionDrop {
				t.Fatalf("step %d: expected drop in low-confidence loop-only window, got %+v", i, d)
			}
			e.dropPackets.Add(1)
		} else if d.Action != rt.ActionForward || d.EgressSession != "dst-smb" {
			t.Fatalf("step %d: expected non-loop forward to dst-smb, got %+v", i, d)
		} else {
			e.forwardPackets.Add(1)
		}

		if i > 0 {
			prev := steps[i-1]
			if d := e.handleIngressSession(makeIPv4(prev.src, dst), rt.SessionKey(prev.owner)); d.Action != rt.ActionDrop {
				t.Fatalf("step %d: stale owner %q must drop, got %+v", i, prev.owner, d)
			}
			e.dropPackets.Add(1)
		}
	}

	m := e.SnapshotMetrics()
	if m.ForwardPackets != 3 || m.DropPackets < 4 || m.ControlErrors != 0 {
		t.Fatalf("unexpected metrics in recommendation-confidence owner-step churn test: %+v", m)
	}
}

func TestEndpointOwnerStepConfidenceBucketShiftLoopbackSymptomWindowTracksMetrics(t *testing.T) {
	e := &Endpoint{
		engine:   rt.NewMemEngine(),
		peerUser: map[rt.RouteID]string{},
		userRef:  map[rt.SessionKey]int{},
		sessions: map[rt.SessionKey]N.PacketConn{},
	}
	for _, owner := range []rt.SessionKey{"owner-a", "owner-b", "owner-c", "dst-a", "dst-b"} {
		e.enterSession(owner)
	}
	t.Cleanup(func() {
		for _, owner := range []rt.SessionKey{"dst-b", "dst-a", "owner-c", "owner-b", "owner-a"} {
			e.leaveSession(owner)
		}
	})
	mustUpsert := func(route rt.Route) {
		t.Helper()
		if err := e.UpsertRoute(route); err != nil {
			t.Fatalf("upsert peer %d(%s): %v", route.PeerID, route.User, err)
		}
	}

	mustUpsert(rt.Route{
		PeerID:               1661,
		User:                 "owner-a",
		FilterSourceIPs:      []netip.Prefix{netip.MustParsePrefix("10.243.0.0/24")},
		FilterDestinationIPs: []netip.Prefix{netip.MustParsePrefix("10.243.9.0/24")},
		AllowedIPs:           []netip.Prefix{netip.MustParsePrefix("10.243.0.0/24")},
	})
	mustUpsert(rt.Route{PeerID: 1662, User: "owner-a", AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.243.9.0/24")}})
	mustUpsert(rt.Route{PeerID: 1663, User: "dst-a", AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.243.9.0/24")}})
	mustUpsert(rt.Route{PeerID: 1664, User: "dst-b", AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.243.9.0/24")}})
	e.setEgressSessionForTesting(1663, "dst-a")
	e.setEgressSessionForTesting(1664, "dst-b")

	steps := []struct {
		owner      string
		src        [4]byte
		cidr       string
		withdrawA  bool
		withdrawB  bool
		expectDest rt.SessionKey
	}{
		{owner: "owner-a", src: [4]byte{10, 243, 0, 10}, cidr: "10.243.0.0/24", expectDest: "dst-a"},
		{owner: "owner-b", src: [4]byte{10, 243, 1, 10}, cidr: "10.243.1.0/24", withdrawA: true, expectDest: "dst-b"},
		{owner: "owner-c", src: [4]byte{10, 243, 2, 10}, cidr: "10.243.2.0/24", withdrawA: true, withdrawB: true},
		{owner: "owner-b", src: [4]byte{10, 243, 3, 10}, cidr: "10.243.3.0/24", expectDest: "dst-a"},
	}
	dst := [4]byte{10, 243, 9, 44}
	for i, s := range steps {
		mustUpsert(rt.Route{
			PeerID:               1661,
			User:                 s.owner,
			FilterSourceIPs:      []netip.Prefix{netip.MustParsePrefix(s.cidr)},
			FilterDestinationIPs: []netip.Prefix{netip.MustParsePrefix("10.243.9.0/24")},
			AllowedIPs:           []netip.Prefix{netip.MustParsePrefix(s.cidr)},
		})
		e.setEgressSessionForTesting(1662, rt.SessionKey(s.owner))
		if s.withdrawA {
			e.RemoveRoute(1663)
		} else {
			mustUpsert(rt.Route{PeerID: 1663, User: "dst-a", AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.243.9.0/24")}})
			e.setEgressSessionForTesting(1663, "dst-a")
		}
		if s.withdrawB {
			e.RemoveRoute(1664)
		} else {
			mustUpsert(rt.Route{PeerID: 1664, User: "dst-b", AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.243.9.0/24")}})
			e.setEgressSessionForTesting(1664, "dst-b")
		}

		d := e.handleIngressSession(makeIPv4(s.src, dst), rt.SessionKey(s.owner))
		if s.expectDest == "" {
			if d.Action != rt.ActionDrop {
				t.Fatalf("step %d: expected drop in bucket-shift loopback symptom window, got %+v", i, d)
			}
			e.dropPackets.Add(1)
		} else if d.Action != rt.ActionForward || d.EgressSession != s.expectDest {
			t.Fatalf("step %d: expected non-loop forward to %q, got %+v", i, s.expectDest, d)
		} else {
			e.forwardPackets.Add(1)
		}
		if d.Action == rt.ActionForward && d.EgressSession == rt.SessionKey(s.owner) {
			t.Fatalf("step %d: self-loop detected %+v", i, d)
		}
		if i > 0 {
			prev := steps[i-1]
			if dPrev := e.handleIngressSession(makeIPv4(prev.src, dst), rt.SessionKey(prev.owner)); dPrev.Action != rt.ActionDrop {
				t.Fatalf("step %d: stale owner %q must drop, got %+v", i, prev.owner, dPrev)
			}
			e.dropPackets.Add(1)
		}
	}

	m := e.SnapshotMetrics()
	if m.ForwardPackets != 3 || m.DropPackets < 4 || m.ControlErrors != 0 {
		t.Fatalf("unexpected metrics in confidence-bucket shift loopback symptom test: %+v", m)
	}
}

func TestEndpointOwnerStepAnomalyClusterRotationKeepsNoLoopAndMetrics(t *testing.T) {
	e := &Endpoint{
		engine:   rt.NewMemEngine(),
		peerUser: map[rt.RouteID]string{},
		userRef:  map[rt.SessionKey]int{},
		sessions: map[rt.SessionKey]N.PacketConn{},
	}
	for _, owner := range []rt.SessionKey{"owner-a", "owner-b", "owner-c", "dst-smb"} {
		e.enterSession(owner)
	}
	t.Cleanup(func() {
		for _, owner := range []rt.SessionKey{"dst-smb", "owner-c", "owner-b", "owner-a"} {
			e.leaveSession(owner)
		}
	})
	mustUpsert := func(route rt.Route) {
		t.Helper()
		if err := e.UpsertRoute(route); err != nil {
			t.Fatalf("upsert peer %d(%s): %v", route.PeerID, route.User, err)
		}
	}

	mustUpsert(rt.Route{
		PeerID:               1501,
		User:                 "owner-a",
		FilterSourceIPs:      []netip.Prefix{netip.MustParsePrefix("10.245.0.0/24")},
		FilterDestinationIPs: []netip.Prefix{netip.MustParsePrefix("10.245.9.0/24")},
		AllowedIPs:           []netip.Prefix{netip.MustParsePrefix("10.245.0.0/24")},
	})
	mustUpsert(rt.Route{PeerID: 1502, User: "owner-a", AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.245.9.0/24")}})
	mustUpsert(rt.Route{PeerID: 1503, User: "dst-smb", AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.245.9.0/24")}})
	e.setEgressSessionForTesting(1503, "dst-smb")

	steps := []struct {
		owner string
		src   [4]byte
		cidr  string
	}{
		{owner: "owner-a", src: [4]byte{10, 245, 0, 10}, cidr: "10.245.0.0/24"},
		{owner: "owner-b", src: [4]byte{10, 245, 1, 10}, cidr: "10.245.1.0/24"},
		{owner: "owner-c", src: [4]byte{10, 245, 2, 10}, cidr: "10.245.2.0/24"},
	}
	dst := [4]byte{10, 245, 9, 44}
	for i, s := range steps {
		mustUpsert(rt.Route{
			PeerID:               1501,
			User:                 s.owner,
			FilterSourceIPs:      []netip.Prefix{netip.MustParsePrefix(s.cidr)},
			FilterDestinationIPs: []netip.Prefix{netip.MustParsePrefix("10.245.9.0/24")},
			AllowedIPs:           []netip.Prefix{netip.MustParsePrefix(s.cidr)},
		})
		e.setEgressSessionForTesting(1502, rt.SessionKey(s.owner))

		d := e.handleIngressSession(makeIPv4(s.src, dst), rt.SessionKey(s.owner))
		if d.Action != rt.ActionForward || d.EgressSession != "dst-smb" {
			t.Fatalf("step %d: expected non-loop forward to dst-smb, got %+v", i, d)
		}
		if d.EgressSession == rt.SessionKey(s.owner) {
			t.Fatalf("step %d: self-loop detected %+v", i, d)
		}
		e.forwardPackets.Add(1)

		if i > 0 {
			prev := steps[i-1]
			if dPrev := e.handleIngressSession(makeIPv4(prev.src, dst), rt.SessionKey(prev.owner)); dPrev.Action != rt.ActionDrop {
				t.Fatalf("step %d: stale owner %q must drop, got %+v", i, prev.owner, dPrev)
			}
			e.dropPackets.Add(1)
		}
	}

	m := e.SnapshotMetrics()
	if m.ForwardPackets != 3 || m.DropPackets != 2 || m.ControlErrors != 0 {
		t.Fatalf("unexpected metrics in anomaly-cluster owner rotation test: %+v", m)
	}
}

func TestEndpointOwnerStepRiskScorePatternQueueReadinessTracksNoLoopAndMetrics(t *testing.T) {
	e := &Endpoint{
		engine:   rt.NewMemEngine(),
		peerUser: map[rt.RouteID]string{},
		userRef:  map[rt.SessionKey]int{},
		sessions: map[rt.SessionKey]N.PacketConn{},
	}
	for _, owner := range []rt.SessionKey{"owner-a", "owner-b", "owner-c", "dst-a", "dst-b"} {
		e.enterSession(owner)
	}
	t.Cleanup(func() {
		for _, owner := range []rt.SessionKey{"dst-b", "dst-a", "owner-c", "owner-b", "owner-a"} {
			e.leaveSession(owner)
		}
	})
	mustUpsert := func(route rt.Route) {
		t.Helper()
		if err := e.UpsertRoute(route); err != nil {
			t.Fatalf("upsert peer %d(%s): %v", route.PeerID, route.User, err)
		}
	}

	mustUpsert(rt.Route{
		PeerID:               1701,
		User:                 "owner-a",
		FilterSourceIPs:      []netip.Prefix{netip.MustParsePrefix("10.251.0.0/24")},
		FilterDestinationIPs: []netip.Prefix{netip.MustParsePrefix("10.251.9.0/24")},
		AllowedIPs:           []netip.Prefix{netip.MustParsePrefix("10.251.0.0/24")},
	})
	mustUpsert(rt.Route{PeerID: 1702, User: "owner-a", AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.251.9.0/24")}})
	mustUpsert(rt.Route{PeerID: 1703, User: "dst-a", AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.251.9.0/24")}})
	mustUpsert(rt.Route{PeerID: 1704, User: "dst-b", AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.251.9.0/24")}})
	e.setEgressSessionForTesting(1703, "dst-a")
	e.setEgressSessionForTesting(1704, "dst-b")

	steps := []struct {
		owner      string
		src        [4]byte
		cidr       string
		withdrawA  bool
		withdrawB  bool
		expectDest rt.SessionKey
	}{
		{owner: "owner-a", src: [4]byte{10, 251, 0, 10}, cidr: "10.251.0.0/24", expectDest: "dst-a"},
		{owner: "owner-b", src: [4]byte{10, 251, 1, 10}, cidr: "10.251.1.0/24", withdrawA: true, expectDest: "dst-b"},
		{owner: "owner-c", src: [4]byte{10, 251, 2, 10}, cidr: "10.251.2.0/24", withdrawA: true, withdrawB: true},
		{owner: "owner-a", src: [4]byte{10, 251, 3, 10}, cidr: "10.251.3.0/24", expectDest: "dst-a"},
	}
	dst := [4]byte{10, 251, 9, 44}
	for i, s := range steps {
		mustUpsert(rt.Route{
			PeerID:               1701,
			User:                 s.owner,
			FilterSourceIPs:      []netip.Prefix{netip.MustParsePrefix(s.cidr)},
			FilterDestinationIPs: []netip.Prefix{netip.MustParsePrefix("10.251.9.0/24")},
			AllowedIPs:           []netip.Prefix{netip.MustParsePrefix(s.cidr)},
		})
		e.setEgressSessionForTesting(1702, rt.SessionKey(s.owner))

		if s.withdrawA {
			e.RemoveRoute(1703)
		} else {
			mustUpsert(rt.Route{PeerID: 1703, User: "dst-a", AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.251.9.0/24")}})
			e.setEgressSessionForTesting(1703, "dst-a")
		}
		if s.withdrawB {
			e.RemoveRoute(1704)
		} else {
			mustUpsert(rt.Route{PeerID: 1704, User: "dst-b", AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.251.9.0/24")}})
			e.setEgressSessionForTesting(1704, "dst-b")
		}

		d := e.handleIngressSession(makeIPv4(s.src, dst), rt.SessionKey(s.owner))
		if s.expectDest == "" {
			if d.Action != rt.ActionDrop {
				t.Fatalf("step %d: expected drop in risk-score queue pattern, got %+v", i, d)
			}
			e.dropPackets.Add(1)
		} else if d.Action != rt.ActionForward || d.EgressSession != s.expectDest {
			t.Fatalf("step %d: expected forward to %q, got %+v", i, s.expectDest, d)
		} else {
			e.forwardPackets.Add(1)
		}
		if d.Action == rt.ActionForward && d.EgressSession == rt.SessionKey(s.owner) {
			t.Fatalf("step %d: self-loop detected %+v", i, d)
		}
		if i > 0 {
			prev := steps[i-1]
			if dPrev := e.handleIngressSession(makeIPv4(prev.src, dst), rt.SessionKey(prev.owner)); dPrev.Action != rt.ActionDrop {
				t.Fatalf("step %d: stale owner %q must drop, got %+v", i, prev.owner, dPrev)
			}
			e.dropPackets.Add(1)
		}
	}

	m := e.SnapshotMetrics()
	if m.ForwardPackets != 3 || m.DropPackets < 4 || m.ControlErrors != 0 {
		t.Fatalf("unexpected metrics in risk-score queue readiness test: %+v", m)
	}
}

func TestEndpointOwnerStepSustainedHighRiskFailOnlyWindowTracksNoLoopMetrics(t *testing.T) {
	e := &Endpoint{
		engine:   rt.NewMemEngine(),
		peerUser: map[rt.RouteID]string{},
		userRef:  map[rt.SessionKey]int{},
		sessions: map[rt.SessionKey]N.PacketConn{},
	}
	for _, owner := range []rt.SessionKey{"owner-a", "owner-b", "owner-c", "dst-a", "dst-b"} {
		e.enterSession(owner)
	}
	t.Cleanup(func() {
		for _, owner := range []rt.SessionKey{"dst-b", "dst-a", "owner-c", "owner-b", "owner-a"} {
			e.leaveSession(owner)
		}
	})
	mustUpsert := func(route rt.Route) {
		t.Helper()
		if err := e.UpsertRoute(route); err != nil {
			t.Fatalf("upsert peer %d(%s): %v", route.PeerID, route.User, err)
		}
	}

	mustUpsert(rt.Route{
		PeerID:               1711,
		User:                 "owner-a",
		FilterSourceIPs:      []netip.Prefix{netip.MustParsePrefix("10.252.0.0/24")},
		FilterDestinationIPs: []netip.Prefix{netip.MustParsePrefix("10.252.9.0/24")},
		AllowedIPs:           []netip.Prefix{netip.MustParsePrefix("10.252.0.0/24")},
	})
	mustUpsert(rt.Route{PeerID: 1712, User: "owner-a", AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.252.9.0/24")}})
	mustUpsert(rt.Route{PeerID: 1713, User: "dst-a", AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.252.9.0/24")}})
	mustUpsert(rt.Route{PeerID: 1714, User: "dst-b", AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.252.9.0/24")}})
	e.setEgressSessionForTesting(1713, "dst-a")
	e.setEgressSessionForTesting(1714, "dst-b")

	steps := []struct {
		owner      string
		src        [4]byte
		cidr       string
		withdrawA  bool
		withdrawB  bool
		expectDest rt.SessionKey
	}{
		{owner: "owner-a", src: [4]byte{10, 252, 0, 10}, cidr: "10.252.0.0/24", expectDest: "dst-a"},
		{owner: "owner-b", src: [4]byte{10, 252, 1, 10}, cidr: "10.252.1.0/24", withdrawA: true, expectDest: "dst-b"},
		{owner: "owner-c", src: [4]byte{10, 252, 2, 10}, cidr: "10.252.2.0/24", withdrawA: true, withdrawB: true},
		{owner: "owner-a", src: [4]byte{10, 252, 3, 10}, cidr: "10.252.3.0/24", withdrawA: true, withdrawB: true},
		{owner: "owner-b", src: [4]byte{10, 252, 4, 10}, cidr: "10.252.4.0/24", expectDest: "dst-a"},
	}
	dst := [4]byte{10, 252, 9, 44}
	for i, s := range steps {
		mustUpsert(rt.Route{
			PeerID:               1711,
			User:                 s.owner,
			FilterSourceIPs:      []netip.Prefix{netip.MustParsePrefix(s.cidr)},
			FilterDestinationIPs: []netip.Prefix{netip.MustParsePrefix("10.252.9.0/24")},
			AllowedIPs:           []netip.Prefix{netip.MustParsePrefix(s.cidr)},
		})
		e.setEgressSessionForTesting(1712, rt.SessionKey(s.owner))

		if s.withdrawA {
			e.RemoveRoute(1713)
		} else {
			mustUpsert(rt.Route{PeerID: 1713, User: "dst-a", AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.252.9.0/24")}})
			e.setEgressSessionForTesting(1713, "dst-a")
		}
		if s.withdrawB {
			e.RemoveRoute(1714)
		} else {
			mustUpsert(rt.Route{PeerID: 1714, User: "dst-b", AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.252.9.0/24")}})
			e.setEgressSessionForTesting(1714, "dst-b")
		}

		d := e.handleIngressSession(makeIPv4(s.src, dst), rt.SessionKey(s.owner))
		if s.expectDest == "" {
			if d.Action != rt.ActionDrop {
				t.Fatalf("step %d: expected drop in sustained high-risk fail-only window, got %+v", i, d)
			}
			e.dropPackets.Add(1)
		} else if d.Action != rt.ActionForward || d.EgressSession != s.expectDest {
			t.Fatalf("step %d: expected forward to %q, got %+v", i, s.expectDest, d)
		} else {
			e.forwardPackets.Add(1)
		}
		if d.Action == rt.ActionForward && d.EgressSession == rt.SessionKey(s.owner) {
			t.Fatalf("step %d: self-loop detected %+v", i, d)
		}
	}

	m := e.SnapshotMetrics()
	if m.ForwardPackets != 3 || m.DropPackets < 2 || m.ControlErrors != 0 {
		t.Fatalf("unexpected metrics in sustained high-risk fail-only test: %+v", m)
	}
}

func TestEndpointOwnerStepRiskTierQueueTraceWindowKeepsNoLoopAndMetrics(t *testing.T) {
	e := &Endpoint{
		engine:   rt.NewMemEngine(),
		peerUser: map[rt.RouteID]string{},
		userRef:  map[rt.SessionKey]int{},
		sessions: map[rt.SessionKey]N.PacketConn{},
	}
	for _, owner := range []rt.SessionKey{"owner-a", "owner-b", "owner-c", "dst-a", "dst-b"} {
		e.enterSession(owner)
	}
	t.Cleanup(func() {
		for _, owner := range []rt.SessionKey{"dst-b", "dst-a", "owner-c", "owner-b", "owner-a"} {
			e.leaveSession(owner)
		}
	})
	mustUpsert := func(route rt.Route) {
		t.Helper()
		if err := e.UpsertRoute(route); err != nil {
			t.Fatalf("upsert peer %d(%s): %v", route.PeerID, route.User, err)
		}
	}

	mustUpsert(rt.Route{
		PeerID:               1721,
		User:                 "owner-a",
		FilterSourceIPs:      []netip.Prefix{netip.MustParsePrefix("10.253.0.0/24")},
		FilterDestinationIPs: []netip.Prefix{netip.MustParsePrefix("10.253.9.0/24")},
		AllowedIPs:           []netip.Prefix{netip.MustParsePrefix("10.253.0.0/24")},
	})
	mustUpsert(rt.Route{PeerID: 1722, User: "owner-a", AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.253.9.0/24")}})
	mustUpsert(rt.Route{PeerID: 1723, User: "dst-a", AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.253.9.0/24")}})
	mustUpsert(rt.Route{PeerID: 1724, User: "dst-b", AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.253.9.0/24")}})
	e.setEgressSessionForTesting(1723, "dst-a")
	e.setEgressSessionForTesting(1724, "dst-b")

	steps := []struct {
		owner      string
		src        [4]byte
		cidr       string
		withdrawA  bool
		withdrawB  bool
		expectDest rt.SessionKey
	}{
		{owner: "owner-a", src: [4]byte{10, 253, 0, 10}, cidr: "10.253.0.0/24", expectDest: "dst-a"},
		{owner: "owner-b", src: [4]byte{10, 253, 1, 10}, cidr: "10.253.1.0/24", withdrawA: true, expectDest: "dst-b"},
		{owner: "owner-c", src: [4]byte{10, 253, 2, 10}, cidr: "10.253.2.0/24", withdrawA: true, withdrawB: true},
		{owner: "owner-a", src: [4]byte{10, 253, 3, 10}, cidr: "10.253.3.0/24", withdrawA: true, withdrawB: true},
		{owner: "owner-b", src: [4]byte{10, 253, 4, 10}, cidr: "10.253.4.0/24", expectDest: "dst-a"},
	}
	dst := [4]byte{10, 253, 9, 44}
	for i, s := range steps {
		mustUpsert(rt.Route{
			PeerID:               1721,
			User:                 s.owner,
			FilterSourceIPs:      []netip.Prefix{netip.MustParsePrefix(s.cidr)},
			FilterDestinationIPs: []netip.Prefix{netip.MustParsePrefix("10.253.9.0/24")},
			AllowedIPs:           []netip.Prefix{netip.MustParsePrefix(s.cidr)},
		})
		e.setEgressSessionForTesting(1722, rt.SessionKey(s.owner))

		if s.withdrawA {
			e.RemoveRoute(1723)
		} else {
			mustUpsert(rt.Route{PeerID: 1723, User: "dst-a", AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.253.9.0/24")}})
			e.setEgressSessionForTesting(1723, "dst-a")
		}
		if s.withdrawB {
			e.RemoveRoute(1724)
		} else {
			mustUpsert(rt.Route{PeerID: 1724, User: "dst-b", AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.253.9.0/24")}})
			e.setEgressSessionForTesting(1724, "dst-b")
		}

		d := e.handleIngressSession(makeIPv4(s.src, dst), rt.SessionKey(s.owner))
		if s.expectDest == "" {
			if d.Action != rt.ActionDrop {
				t.Fatalf("step %d: expected drop in risk-tier queue trace window, got %+v", i, d)
			}
			e.dropPackets.Add(1)
		} else if d.Action != rt.ActionForward || d.EgressSession != s.expectDest {
			t.Fatalf("step %d: expected forward to %q, got %+v", i, s.expectDest, d)
		} else {
			e.forwardPackets.Add(1)
		}
		if d.Action == rt.ActionForward && d.EgressSession == rt.SessionKey(s.owner) {
			t.Fatalf("step %d: self-loop detected %+v", i, d)
		}
		if i > 0 {
			prev := steps[i-1]
			if dPrev := e.handleIngressSession(makeIPv4(prev.src, dst), rt.SessionKey(prev.owner)); dPrev.Action != rt.ActionDrop {
				t.Fatalf("step %d: stale owner %q must drop, got %+v", i, prev.owner, dPrev)
			}
			e.dropPackets.Add(1)
		}
	}

	m := e.SnapshotMetrics()
	if m.ForwardPackets < 3 || m.DropPackets < 4 || m.ControlErrors != 0 {
		t.Fatalf("unexpected metrics in risk-tier queue trace test: %+v", m)
	}
}

func TestEndpointOwnerStepRiskTierJitterBudgetWindowKeepsNoLoopAndMetrics(t *testing.T) {
	e := &Endpoint{
		engine:   rt.NewMemEngine(),
		peerUser: map[rt.RouteID]string{},
		userRef:  map[rt.SessionKey]int{},
		sessions: map[rt.SessionKey]N.PacketConn{},
	}
	for _, owner := range []rt.SessionKey{"owner-a", "owner-b", "owner-c", "dst-a", "dst-b"} {
		e.enterSession(owner)
	}
	t.Cleanup(func() {
		for _, owner := range []rt.SessionKey{"dst-b", "dst-a", "owner-c", "owner-b", "owner-a"} {
			e.leaveSession(owner)
		}
	})
	mustUpsert := func(route rt.Route) {
		t.Helper()
		if err := e.UpsertRoute(route); err != nil {
			t.Fatalf("upsert peer %d(%s): %v", route.PeerID, route.User, err)
		}
	}

	mustUpsert(rt.Route{
		PeerID:               1731,
		User:                 "owner-a",
		FilterSourceIPs:      []netip.Prefix{netip.MustParsePrefix("10.254.0.0/24")},
		FilterDestinationIPs: []netip.Prefix{netip.MustParsePrefix("10.254.9.0/24")},
		AllowedIPs:           []netip.Prefix{netip.MustParsePrefix("10.254.0.0/24")},
	})
	mustUpsert(rt.Route{PeerID: 1732, User: "owner-a", AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.254.9.0/24")}})
	mustUpsert(rt.Route{PeerID: 1733, User: "dst-a", AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.254.9.0/24")}})
	mustUpsert(rt.Route{PeerID: 1734, User: "dst-b", AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.254.9.0/24")}})
	e.setEgressSessionForTesting(1733, "dst-a")
	e.setEgressSessionForTesting(1734, "dst-b")

	steps := []struct {
		owner      string
		src        [4]byte
		cidr       string
		tier       string
		jitter     bool
		expectDest rt.SessionKey
	}{
		{owner: "owner-c", src: [4]byte{10, 254, 3, 10}, cidr: "10.254.3.0/24", tier: "P3", jitter: true, expectDest: "dst-a"},
		{owner: "owner-b", src: [4]byte{10, 254, 2, 10}, cidr: "10.254.2.0/24", tier: "P2", jitter: true, expectDest: "dst-a"},
		{owner: "owner-a", src: [4]byte{10, 254, 1, 10}, cidr: "10.254.1.0/24", tier: "P1", jitter: false, expectDest: "dst-a"},
	}
	dst := [4]byte{10, 254, 9, 40}
	for i, s := range steps {
		mustUpsert(rt.Route{
			PeerID:               1731,
			User:                 s.owner,
			FilterSourceIPs:      []netip.Prefix{netip.MustParsePrefix(s.cidr)},
			FilterDestinationIPs: []netip.Prefix{netip.MustParsePrefix("10.254.9.0/24")},
			AllowedIPs:           []netip.Prefix{netip.MustParsePrefix(s.cidr)},
		})
		e.setEgressSessionForTesting(1732, rt.SessionKey(s.owner))

		if s.jitter && s.tier != "P3" {
			e.RemoveRoute(1733)
			e.RemoveRoute(1734)
			if d := e.handleIngressSession(makeIPv4(s.src, dst), rt.SessionKey(s.owner)); d.Action != rt.ActionDrop {
				t.Fatalf("step %d (%s): expected drop in loop-only jitter window, got %+v", i, s.tier, d)
			}
			e.dropPackets.Add(1)
			mustUpsert(rt.Route{PeerID: 1733, User: "dst-a", AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.254.9.0/24")}})
			mustUpsert(rt.Route{PeerID: 1734, User: "dst-b", AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.254.9.0/24")}})
			e.setEgressSessionForTesting(1733, "dst-a")
			e.setEgressSessionForTesting(1734, "dst-b")
		}

		d := e.handleIngressSession(makeIPv4(s.src, dst), rt.SessionKey(s.owner))
		if d.Action != rt.ActionForward || d.EgressSession != s.expectDest {
			t.Fatalf("step %d (%s): expected deterministic forward to %q, got %+v", i, s.tier, s.expectDest, d)
		}
		if d.EgressSession == rt.SessionKey(s.owner) {
			t.Fatalf("step %d (%s): self-loop detected %+v", i, s.tier, d)
		}
		e.forwardPackets.Add(1)
		if i > 0 {
			prev := steps[i-1]
			if dPrev := e.handleIngressSession(makeIPv4(prev.src, dst), rt.SessionKey(prev.owner)); dPrev.Action != rt.ActionDrop {
				t.Fatalf("step %d: stale owner %q must drop, got %+v", i, prev.owner, dPrev)
			}
			e.dropPackets.Add(1)
		}
	}

	m := e.SnapshotMetrics()
	if m.ForwardPackets != 3 || m.DropPackets < 3 || m.ControlErrors != 0 {
		t.Fatalf("unexpected metrics in risk-tier jitter-budget test: %+v", m)
	}
}

func TestEndpointOwnerStepDeterministicQueueTieBreakWindowNoLoopAndMetrics(t *testing.T) {
	e := &Endpoint{
		engine:   rt.NewMemEngine(),
		peerUser: map[rt.RouteID]string{},
		userRef:  map[rt.SessionKey]int{},
		sessions: map[rt.SessionKey]N.PacketConn{},
	}
	for _, owner := range []rt.SessionKey{"owner-a", "owner-b", "owner-c", "dst-low", "dst-high"} {
		e.enterSession(owner)
	}
	t.Cleanup(func() {
		for _, owner := range []rt.SessionKey{"dst-high", "dst-low", "owner-c", "owner-b", "owner-a"} {
			e.leaveSession(owner)
		}
	})
	mustUpsert := func(route rt.Route) {
		t.Helper()
		if err := e.UpsertRoute(route); err != nil {
			t.Fatalf("upsert peer %d(%s): %v", route.PeerID, route.User, err)
		}
	}
	mustUpsert(rt.Route{
		PeerID:               1741,
		User:                 "owner-a",
		FilterSourceIPs:      []netip.Prefix{netip.MustParsePrefix("10.255.0.0/24")},
		FilterDestinationIPs: []netip.Prefix{netip.MustParsePrefix("10.255.9.0/24")},
		AllowedIPs:           []netip.Prefix{netip.MustParsePrefix("10.255.0.0/24")},
	})
	mustUpsert(rt.Route{PeerID: 1742, User: "owner-a", AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.255.9.0/24")}})
	mustUpsert(rt.Route{PeerID: 1743, User: "dst-low", AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.255.9.0/24")}})
	mustUpsert(rt.Route{PeerID: 1744, User: "dst-high", AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.255.9.0/24")}})
	e.setEgressSessionForTesting(1743, "dst-low")
	e.setEgressSessionForTesting(1744, "dst-high")

	src := [4]byte{10, 255, 0, 11}
	dst := [4]byte{10, 255, 9, 41}
	owners := []string{"owner-c", "owner-b", "owner-a", "owner-c", "owner-a", "owner-b"}
	expected := []rt.SessionKey{"dst-low", "dst-high", "dst-low", "dst-high", "dst-low", "dst-high"}
	for i, owner := range owners {
		mustUpsert(rt.Route{
			PeerID:               1741,
			User:                 owner,
			FilterSourceIPs:      []netip.Prefix{netip.MustParsePrefix("10.255.0.0/24")},
			FilterDestinationIPs: []netip.Prefix{netip.MustParsePrefix("10.255.9.0/24")},
			AllowedIPs:           []netip.Prefix{netip.MustParsePrefix("10.255.0.0/24")},
		})
		e.setEgressSessionForTesting(1742, rt.SessionKey(owner))
		if i%2 == 0 {
			e.RemoveRoute(1744)
			mustUpsert(rt.Route{PeerID: 1743, User: "dst-low", AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.255.9.0/24")}})
			e.setEgressSessionForTesting(1743, "dst-low")
		} else {
			e.RemoveRoute(1743)
			mustUpsert(rt.Route{PeerID: 1744, User: "dst-high", AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.255.9.0/24")}})
			e.setEgressSessionForTesting(1744, "dst-high")
		}
		d := e.handleIngressSession(makeIPv4(src, dst), rt.SessionKey(owner))
		if d.Action != rt.ActionForward || d.EgressSession != expected[i] {
			t.Fatalf("step %d: expected stable forward to %q, got %+v", i, expected[i], d)
		}
		if d.EgressSession == rt.SessionKey(owner) {
			t.Fatalf("step %d: self-loop detected %+v", i, d)
		}
		e.forwardPackets.Add(1)
		if i > 0 {
			prevOwner := rt.SessionKey(owners[i-1])
			if stale := e.handleIngressSession(makeIPv4(src, dst), prevOwner); stale.Action != rt.ActionDrop {
				t.Fatalf("step %d: stale owner %q must drop, got %+v", i, prevOwner, stale)
			}
			e.dropPackets.Add(1)
		}
	}

	m := e.SnapshotMetrics()
	if m.ForwardPackets != uint64(len(owners)) || m.DropPackets < uint64(len(owners)-1) || m.ControlErrors != 0 {
		t.Fatalf("unexpected metrics in deterministic tie-break test: %+v", m)
	}
}

func TestEndpointOwnerStepJitterBudgetOverrunWindowDropsLoopOnlyAndRecoversWithoutSelfLoop(t *testing.T) {
	e := &Endpoint{
		engine:   rt.NewMemEngine(),
		peerUser: map[rt.RouteID]string{},
		userRef:  map[rt.SessionKey]int{},
		sessions: map[rt.SessionKey]N.PacketConn{},
	}
	for _, owner := range []rt.SessionKey{"owner-a", "owner-b", "owner-c", "dst-low", "dst-high"} {
		e.enterSession(owner)
	}
	t.Cleanup(func() {
		for _, owner := range []rt.SessionKey{"dst-high", "dst-low", "owner-c", "owner-b", "owner-a"} {
			e.leaveSession(owner)
		}
	})
	mustUpsert := func(route rt.Route) {
		t.Helper()
		if err := e.UpsertRoute(route); err != nil {
			t.Fatalf("upsert peer %d(%s): %v", route.PeerID, route.User, err)
		}
	}
	mustUpsert(rt.Route{
		PeerID:               1751,
		User:                 "owner-a",
		FilterSourceIPs:      []netip.Prefix{netip.MustParsePrefix("10.255.10.0/24")},
		FilterDestinationIPs: []netip.Prefix{netip.MustParsePrefix("10.255.11.0/24")},
		AllowedIPs:           []netip.Prefix{netip.MustParsePrefix("10.255.10.0/24")},
	})
	mustUpsert(rt.Route{PeerID: 1752, User: "owner-a", AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.255.11.0/24")}})
	mustUpsert(rt.Route{PeerID: 1753, User: "dst-low", AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.255.11.0/24")}})
	mustUpsert(rt.Route{PeerID: 1754, User: "dst-high", AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.255.11.0/24")}})
	e.setEgressSessionForTesting(1753, "dst-low")
	e.setEgressSessionForTesting(1754, "dst-high")
	src := [4]byte{10, 255, 10, 11}
	dst := [4]byte{10, 255, 11, 41}
	owners := []string{"owner-a", "owner-b", "owner-c", "owner-a", "owner-b", "owner-c"}

	for i, owner := range owners {
		mustUpsert(rt.Route{
			PeerID:               1751,
			User:                 owner,
			FilterSourceIPs:      []netip.Prefix{netip.MustParsePrefix("10.255.10.0/24")},
			FilterDestinationIPs: []netip.Prefix{netip.MustParsePrefix("10.255.11.0/24")},
			AllowedIPs:           []netip.Prefix{netip.MustParsePrefix("10.255.10.0/24")},
		})
		e.setEgressSessionForTesting(1752, rt.SessionKey(owner))
		if i < 3 {
			e.RemoveRoute(1753)
			e.RemoveRoute(1754)
			if d := e.handleIngressSession(makeIPv4(src, dst), rt.SessionKey(owner)); d.Action != rt.ActionDrop {
				t.Fatalf("step %d: expected drop in jitter overrun loop-only window, got %+v", i, d)
			}
			e.dropPackets.Add(1)
			mustUpsert(rt.Route{PeerID: 1753, User: "dst-low", AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.255.11.0/24")}})
			mustUpsert(rt.Route{PeerID: 1754, User: "dst-high", AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.255.11.0/24")}})
			e.setEgressSessionForTesting(1753, "dst-low")
			e.setEgressSessionForTesting(1754, "dst-high")
			continue
		}
		if i%2 == 0 {
			e.RemoveRoute(1754)
			mustUpsert(rt.Route{PeerID: 1753, User: "dst-low", AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.255.11.0/24")}})
			e.setEgressSessionForTesting(1753, "dst-low")
		} else {
			e.RemoveRoute(1753)
			mustUpsert(rt.Route{PeerID: 1754, User: "dst-high", AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.255.11.0/24")}})
			e.setEgressSessionForTesting(1754, "dst-high")
		}
		d := e.handleIngressSession(makeIPv4(src, dst), rt.SessionKey(owner))
		if d.Action != rt.ActionForward || d.EgressSession == rt.SessionKey(owner) {
			t.Fatalf("step %d: expected non-loop forward after recovery, got %+v", i, d)
		}
		e.forwardPackets.Add(1)
	}
	m := e.SnapshotMetrics()
	if m.DropPackets < 3 || m.ForwardPackets < 3 || m.ControlErrors != 0 {
		t.Fatalf("unexpected metrics in jitter overrun recovery test: %+v", m)
	}
}

func TestEndpointOwnerStepBudgetOverrunQueueOrderCorrelationTracksFailVsSoftTimeout(t *testing.T) {
	e := &Endpoint{
		engine:   rt.NewMemEngine(),
		peerUser: map[rt.RouteID]string{},
		userRef:  map[rt.SessionKey]int{},
		sessions: map[rt.SessionKey]N.PacketConn{},
	}
	for _, owner := range []rt.SessionKey{"owner-a", "owner-b", "owner-c", "dst-a", "dst-b"} {
		e.enterSession(owner)
	}
	t.Cleanup(func() {
		for _, owner := range []rt.SessionKey{"dst-b", "dst-a", "owner-c", "owner-b", "owner-a"} {
			e.leaveSession(owner)
		}
	})
	mustUpsert := func(route rt.Route) {
		t.Helper()
		if err := e.UpsertRoute(route); err != nil {
			t.Fatalf("upsert peer %d(%s): %v", route.PeerID, route.User, err)
		}
	}
	mustUpsert(rt.Route{
		PeerID:               1761,
		User:                 "owner-a",
		FilterSourceIPs:      []netip.Prefix{netip.MustParsePrefix("10.255.20.0/24")},
		FilterDestinationIPs: []netip.Prefix{netip.MustParsePrefix("10.255.21.0/24")},
		AllowedIPs:           []netip.Prefix{netip.MustParsePrefix("10.255.20.0/24")},
	})
	mustUpsert(rt.Route{PeerID: 1762, User: "owner-a", AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.255.21.0/24")}})
	mustUpsert(rt.Route{PeerID: 1763, User: "dst-a", AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.255.21.0/24")}})
	mustUpsert(rt.Route{PeerID: 1764, User: "dst-b", AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.255.21.0/24")}})
	e.setEgressSessionForTesting(1763, "dst-a")
	e.setEgressSessionForTesting(1764, "dst-b")

	type ownerStep struct {
		owner      string
		cpResult   string
		queueScore int
	}
	steps := []ownerStep{
		{owner: "owner-a", cpResult: "fail", queueScore: 95},
		{owner: "owner-b", cpResult: "ok-soft-timeout", queueScore: 70},
		{owner: "owner-c", cpResult: "ok", queueScore: 30},
	}
	sort.Slice(steps, func(i, j int) bool {
		if steps[i].queueScore == steps[j].queueScore {
			return steps[i].owner < steps[j].owner
		}
		return steps[i].queueScore > steps[j].queueScore
	})
	srcByOwner := map[string][4]byte{
		"owner-a": {10, 255, 20, 11},
		"owner-b": {10, 255, 20, 12},
		"owner-c": {10, 255, 20, 13},
	}
	dst := [4]byte{10, 255, 21, 50}
	for i, step := range steps {
		mustUpsert(rt.Route{
			PeerID:               1761,
			User:                 step.owner,
			FilterSourceIPs:      []netip.Prefix{netip.MustParsePrefix("10.255.20.0/24")},
			FilterDestinationIPs: []netip.Prefix{netip.MustParsePrefix("10.255.21.0/24")},
			AllowedIPs:           []netip.Prefix{netip.MustParsePrefix("10.255.20.0/24")},
		})
		e.setEgressSessionForTesting(1762, rt.SessionKey(step.owner))
		if step.cpResult == "fail" || step.cpResult == "ok-soft-timeout" {
			e.RemoveRoute(1763)
			e.RemoveRoute(1764)
			if d := e.handleIngressSession(makeIPv4(srcByOwner[step.owner], dst), rt.SessionKey(step.owner)); d.Action != rt.ActionDrop {
				t.Fatalf("step %d(%s): expected drop in loop-only window, got %+v", i, step.owner, d)
			}
			e.dropPackets.Add(1)
			mustUpsert(rt.Route{PeerID: 1763, User: "dst-a", AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.255.21.0/24")}})
			mustUpsert(rt.Route{PeerID: 1764, User: "dst-b", AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.255.21.0/24")}})
			e.setEgressSessionForTesting(1763, "dst-a")
			e.setEgressSessionForTesting(1764, "dst-b")
			continue
		}

		d := e.handleIngressSession(makeIPv4(srcByOwner[step.owner], dst), rt.SessionKey(step.owner))
		if d.Action != rt.ActionForward || d.EgressSession != "dst-a" {
			t.Fatalf("step %d(%s): expected deterministic forward to dst-a, got %+v", i, step.owner, d)
		}
		if d.EgressSession == rt.SessionKey(step.owner) {
			t.Fatalf("step %d(%s): self-loop detected %+v", i, step.owner, d)
		}
		e.forwardPackets.Add(1)
	}

	m := e.SnapshotMetrics()
	if m.DropPackets < 2 || m.ForwardPackets < 1 || m.ControlErrors != 0 {
		t.Fatalf("unexpected metrics in budget-overrun correlation test: %+v", m)
	}
}

func makeIPv4(src, dst [4]byte) []byte {
	b := make([]byte, 20)
	b[0] = 0x45
	copy(b[12:16], src[:])
	copy(b[16:20], dst[:])
	return b
}

func makeIPv6(src, dst netip.Addr) []byte {
	b := make([]byte, 40)
	b[0] = 0x60
	src16 := src.As16()
	dst16 := dst.As16()
	copy(b[8:24], src16[:])
	copy(b[24:40], dst16[:])
	return b
}
