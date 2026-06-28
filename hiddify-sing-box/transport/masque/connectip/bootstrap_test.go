package connectip

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"testing"

	cip "github.com/quic-go/connect-ip-go"
)

func TestNewSessionBootstrapParams(t *testing.T) {
	p := NewSessionBootstrapParams("tag1", "cf-connect-ip", "10.0.0.1", "fd00::1")
	if p.Tag != "tag1" || p.WarpConnectIPProtocol != "cf-connect-ip" ||
		p.ProfileLocalIPv4 != "10.0.0.1" || p.ProfileLocalIPv6 != "fd00::1" {
		t.Fatalf("unexpected params: %+v", p)
	}
}

func TestBootstrapRequireAssignedPrefix(t *testing.T) {
	t.Run("default_relaxed", func(t *testing.T) {
		t.Setenv("MASQUE_CONNECT_IP_BOOTSTRAP_REQUIRE_PREFIX", "")
		if BootstrapRequireAssignedPrefix() {
			t.Fatal("expected default relaxed")
		}
	})
	t.Run("opt_in_strict", func(t *testing.T) {
		t.Setenv("MASQUE_CONNECT_IP_BOOTSTRAP_REQUIRE_PREFIX", "1")
		if !BootstrapRequireAssignedPrefix() {
			t.Fatal("expected strict when env=1")
		}
	})
	t.Run("explicit_off", func(t *testing.T) {
		t.Setenv("MASQUE_CONNECT_IP_BOOTSTRAP_REQUIRE_PREFIX", "off")
		if BootstrapRequireAssignedPrefix() {
			t.Fatal("expected relaxed when env=off")
		}
	})
}

func TestWarpConsumerBootstrapSkipsNonWarpProtocol(t *testing.T) {
	conn := &fakeBootstrapConn{}
	if err := WarpConsumerBootstrap(context.Background(), conn, SessionBootstrapParams{
		WarpConnectIPProtocol: "connect-ip",
	}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if conn.requestCalls != 0 {
		t.Fatalf("expected no RequestAddresses, got %d", conn.requestCalls)
	}
}

func TestWarpConsumerBootstrapSkipsLegacyH2WithoutCapsules(t *testing.T) {
	t.Setenv("MASQUE_CONNECT_IP_TCP_NETSTACK_PREFIX_WAIT_SEC", "0")
	conn := &fakeBootstrapConn{controlCapsules: false}
	if err := WarpConsumerBootstrap(context.Background(), conn, SessionBootstrapParams{
		Tag:                   "t1",
		WarpConnectIPProtocol: "cf-connect-ip",
	}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if conn.requestCalls != 0 {
		t.Fatalf("expected no RequestAddresses without control capsules, got %d", conn.requestCalls)
	}
	if len(conn.advertised) != 0 {
		t.Fatalf("expected no AdvertiseRoute without profile local, got %d", len(conn.advertised))
	}
}

func TestWarpConsumerBootstrapLegacyH2ProfileLocalAdvertisesRoutes(t *testing.T) {
	t.Setenv("MASQUE_CONNECT_IP_TCP_NETSTACK_PREFIX_WAIT_SEC", "0")
	conn := &fakeBootstrapConn{controlCapsules: false}
	if err := WarpConsumerBootstrap(context.Background(), conn, SessionBootstrapParams{
		Tag:                   "t1",
		WarpConnectIPProtocol: "cf-connect-ip",
		ProfileLocalIPv4:      "172.16.0.2",
	}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if conn.requestCalls != 0 {
		t.Fatalf("legacy h2 must not RequestAddresses, got %d", conn.requestCalls)
	}
	if len(conn.advertised) != 1 {
		t.Fatalf("expected profile-local AdvertiseRoute fallback, got %d routes", len(conn.advertised))
	}
}

func TestWarpConsumerBootstrapUsesExistingPrefixes(t *testing.T) {
	prefix := netip.MustParsePrefix("172.16.0.2/32")
	conn := &fakeBootstrapConn{
		controlCapsules: true,
		current:         []netip.Prefix{prefix},
	}
	if err := WarpConsumerBootstrap(context.Background(), conn, SessionBootstrapParams{
		Tag:                   "t1",
		WarpConnectIPProtocol: "cf-connect-ip",
	}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if conn.requestCalls != 0 {
		t.Fatalf("expected no RequestAddresses when prefixes already assigned, got %d", conn.requestCalls)
	}
}

func TestWarpConsumerBootstrapRequestAddressesOnEmptyPrefixes(t *testing.T) {
	t.Setenv("MASQUE_CONNECT_IP_TCP_NETSTACK_PREFIX_WAIT_SEC", "0")
	conn := &fakeBootstrapConn{
		controlCapsules: true,
		notify:          make(chan []netip.Prefix),
	}
	if err := WarpConsumerBootstrap(context.Background(), conn, SessionBootstrapParams{
		Tag:                   "t1",
		WarpConnectIPProtocol: "cf-connect-ip",
	}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if conn.requestCalls != 1 {
		t.Fatalf("expected one RequestAddresses(empty), got %d", conn.requestCalls)
	}
}

func TestWarpConsumerBootstrapRequestAddressesErrorClosesConn(t *testing.T) {
	t.Setenv("MASQUE_CONNECT_IP_TCP_NETSTACK_PREFIX_WAIT_SEC", "0")
	conn := &fakeBootstrapConn{
		controlCapsules: true,
		requestErr:      errors.New("request failed"),
	}
	err := WarpConsumerBootstrap(context.Background(), conn, SessionBootstrapParams{
		Tag:                   "t1",
		WarpConnectIPProtocol: "cf-connect-ip",
	})
	if err == nil {
		t.Fatal("expected bootstrap failure")
	}
	if !conn.closed {
		t.Fatal("expected conn closed on request failure")
	}
}

func TestGenericServerBootstrapSkipsWarpProtocol(t *testing.T) {
	conn := &fakeBootstrapConn{}
	if err := GenericServerBootstrap(context.Background(), conn, SessionBootstrapParams{
		WarpConnectIPProtocol: "cf-connect-ip",
	}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestGenericServerBootstrapDoesNotSendEmptyRequest(t *testing.T) {
	conn := &fakeBootstrapConn{controlCapsules: true}
	if err := GenericServerBootstrap(context.Background(), conn, SessionBootstrapParams{Tag: "t1"}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if conn.requestCalls != 0 {
		t.Fatalf("generic server must not send empty ADDRESS_REQUEST, got %d calls", conn.requestCalls)
	}
}

func TestGenericServerBootstrapSkipsRequestWhenPrefixesPresent(t *testing.T) {
	conn := &fakeBootstrapConn{
		controlCapsules: true,
		current:         []netip.Prefix{netip.MustParsePrefix("10.0.0.2/32")},
	}
	if err := GenericServerBootstrap(context.Background(), conn, SessionBootstrapParams{Tag: "t1"}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if conn.requestCalls != 0 {
		t.Fatalf("expected no RequestAddresses when prefixes already assigned, got %d", conn.requestCalls)
	}
}

func TestAdvertiseWarpProfileLocalRoutes(t *testing.T) {
	conn := &fakeBootstrapConn{}
	v4 := netip.MustParseAddr("172.16.0.2")
	if err := AdvertiseWarpProfileLocalRoutes(context.Background(), conn, "172.16.0.2", ""); err != nil {
		t.Fatalf("advertise routes: %v", err)
	}
	if len(conn.advertised) != 1 {
		t.Fatalf("expected one route, got %d", len(conn.advertised))
	}
	if conn.advertised[0].StartIP != v4 {
		t.Fatalf("unexpected route start: %v", conn.advertised[0].StartIP)
	}
}

type fakeBootstrapConn struct {
	controlCapsules bool
	current         []netip.Prefix
	notify          chan []netip.Prefix
	requestCalls    int
	requestErr      error
	advertised      []cip.IPRoute
	closed          bool
}

func (f *fakeBootstrapConn) ControlCapsulesSupported() bool {
	return f.controlCapsules
}

func (f *fakeBootstrapConn) CurrentAssignedPrefixes() []netip.Prefix {
	return slices.Clone(f.current)
}

func (f *fakeBootstrapConn) LocalPrefixes(ctx context.Context) ([]netip.Prefix, error) {
	if f.notify == nil {
		return nil, context.DeadlineExceeded
	}
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case prefixes := <-f.notify:
		f.current = slices.Clone(prefixes)
		return slices.Clone(prefixes), nil
	}
}

func (f *fakeBootstrapConn) RequestAddresses(ctx context.Context, requested []cip.RequestedAddress) error {
	f.requestCalls++
	if len(requested) != 0 {
		return errors.New("expected empty ADDRESS_REQUEST")
	}
	return f.requestErr
}

func (f *fakeBootstrapConn) AdvertiseRoute(ctx context.Context, routes []cip.IPRoute) error {
	f.advertised = append(f.advertised, routes...)
	return nil
}

func (f *fakeBootstrapConn) Close() error {
	f.closed = true
	return nil
}
