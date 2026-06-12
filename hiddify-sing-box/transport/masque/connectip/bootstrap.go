package connectip

import (
	"context"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	cip "github.com/quic-go/connect-ip-go"
)

// BootstrapConn is the connect-ip-go session surface needed for post-dial bootstrap.
type BootstrapConn interface {
	PrefixSource
	ControlCapsulesSupported() bool
	RequestAddresses(ctx context.Context, requested []cip.RequestedAddress) error
	AdvertiseRoute(ctx context.Context, routes []cip.IPRoute) error
	Close() error
}

// SessionBootstrapParams carries CONNECT-IP session fields for ADDRESS_ASSIGN bootstrap.
type SessionBootstrapParams struct {
	Tag                   string
	WarpConnectIPProtocol string
	ProfileLocalIPv4      string
	ProfileLocalIPv6      string
}

// NewSessionBootstrapParams builds bootstrap params from core session option fields.
func NewSessionBootstrapParams(tag, warpConnectIPProtocol, profileLocalIPv4, profileLocalIPv6 string) SessionBootstrapParams {
	return SessionBootstrapParams{
		Tag:                   tag,
		WarpConnectIPProtocol: warpConnectIPProtocol,
		ProfileLocalIPv4:      profileLocalIPv4,
		ProfileLocalIPv6:      profileLocalIPv6,
	}
}

// RunPostDialBootstrap runs WARP consumer and generic server bootstrap after CONNECT-IP dial.
func RunPostDialBootstrap(conn BootstrapConn, p SessionBootstrapParams) error {
	if err := WarpConsumerBootstrap(conn, p); err != nil {
		return err
	}
	return GenericServerBootstrap(conn, p)
}

// BootstrapRequireAssignedPrefix reports MASQUE_CONNECT_IP_BOOTSTRAP_REQUIRE_PREFIX (default relaxed).
func BootstrapRequireAssignedPrefix() bool {
	raw := strings.TrimSpace(os.Getenv("MASQUE_CONNECT_IP_BOOTSTRAP_REQUIRE_PREFIX"))
	if raw == "" {
		// Default relaxed: some live CF colos deliver ADDRESS_ASSIGN only after dataplane
		// starts or with long latency; closing the QUIC stream here breaks the tunnel entirely.
		// TCP netstack creation still waits on LocalPrefixes (see netstack.go).
		// Opt in to fail-closed: MASQUE_CONNECT_IP_BOOTSTRAP_REQUIRE_PREFIX=1
		return false
	}
	raw = strings.ToLower(raw)
	return raw != "0" && raw != "false" && raw != "no" && raw != "off"
}

// AdvertiseWarpProfileLocalRoutes sends ROUTE_ADVERTISEMENT entries for WARP device profile
// interface IPs (when present and sane). connect-ip-go outgoing policy allows sources in either
// ADDRESS_ASSIGN prefixes or locally advertised ranges; without this, gVisor may legitimately use a
// profile local while the edge's assigned prefix is a different /32 — composeDatagram then rejects
// every post-handshake segment (TLS hangs, counters grow, QUIC eventually errors).
//
// When ADDRESS_ASSIGN already provided prefixes, usque does not send ROUTE_ADVERTISEMENT; advertising
// a second (profile) host range here can narrow what the colo delivers on the CONNECT-IP leg while
// incoming policy still accepts packets via assignedAddresses — avoid that path.
func AdvertiseWarpProfileLocalRoutes(ctx context.Context, conn BootstrapConn, profileLocalIPv4, profileLocalIPv6 string) error {
	if conn == nil {
		return nil
	}
	v4 := ParseProfileInterfaceAddress(strings.TrimSpace(profileLocalIPv4))
	v6 := ParseProfileInterfaceAddress(strings.TrimSpace(profileLocalIPv6))
	var routes []cip.IPRoute
	if v4.Is4() {
		routes = append(routes, cip.IPRoute{StartIP: v4, EndIP: v4, IPProtocol: 0})
	}
	if v6.Is6() && !v6.Is4In6() {
		routes = append(routes, cip.IPRoute{StartIP: v6, EndIP: v6, IPProtocol: 0})
	}
	if len(routes) == 0 {
		return nil
	}
	return conn.AdvertiseRoute(ctx, routes)
}

func maybeAdvertiseProfileLocalRoutes(conn BootstrapConn, p SessionBootstrapParams) {
	if conn == nil {
		return
	}
	v4 := ParseProfileInterfaceAddress(strings.TrimSpace(p.ProfileLocalIPv4))
	v6 := ParseProfileInterfaceAddress(strings.TrimSpace(p.ProfileLocalIPv6))
	if !v4.Is4() && !(v6.Is6() && !v6.Is4In6()) {
		return
	}
	tag := strings.TrimSpace(p.Tag)
	advCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := AdvertiseWarpProfileLocalRoutes(advCtx, conn, p.ProfileLocalIPv4, p.ProfileLocalIPv6); err != nil {
		log.Printf("masque connect_ip bootstrap: AdvertiseRoute(profile local) failed tag=%s err=%v", tag, err)
		return
	}
	log.Printf("masque connect_ip bootstrap: AdvertiseRoute(profile local) ok tag=%s", tag)
}

// WarpConsumerBootstrap runs minimal consumer-WARP capsules after CONNECT-IP succeeds (H3/H2).
// usque never sends catch-all AdvertiseRoute nor explicit 0.0.0.0/0 ADDRESS_REQUEST — only an empty
// ADDRESS_REQUEST (RFC9484 peer-specific) matches connect-ip-go docs; the edge then emits ADDRESS_ASSIGN.
func WarpConsumerBootstrap(conn BootstrapConn, p SessionBootstrapParams) error {
	if conn == nil {
		return nil
	}
	tag := strings.TrimSpace(p.Tag)
	proto := strings.TrimSpace(p.WarpConnectIPProtocol)
	if !strings.EqualFold(proto, "cf-connect-ip") {
		return nil
	}
	if !conn.ControlCapsulesSupported() {
		log.Printf("masque connect_ip bootstrap: cf-connect-ip legacy h2 has no control capsules; using profile/local-prefix fallbacks tag=%s", tag)
		return nil
	}
	// MASQUE_CONNECT_IP_SKIP_BOOTSTRAP_CAPSULES must not bypass bootstrap for consumer WARP: without
	// RequestAddresses(empty) the edge often never emits ADDRESS_ASSIGN, gVisor stays on 198.18.0.1,
	// and incoming policy/datapath breaks (TUN-smoke curl timeouts). Log once if set and continue.
	if raw := strings.TrimSpace(os.Getenv("MASQUE_CONNECT_IP_SKIP_BOOTSTRAP_CAPSULES")); raw != "" {
		r := strings.ToLower(raw)
		if r == "1" || r == "true" || r == "yes" || r == "on" {
			log.Printf("masque connect_ip bootstrap: MASQUE_CONNECT_IP_SKIP_BOOTSTRAP_CAPSULES=%q ignored for cf-connect-ip (bootstrap required) tag=%s", raw, tag)
		}
	}
	profileV4 := strings.TrimSpace(p.ProfileLocalIPv4)
	profileV6 := strings.TrimSpace(p.ProfileLocalIPv6)
	policy := NewBootstrapWaitPolicy(
		BootstrapRequireAssignedPrefix(),
		profileV4,
		profileV6,
		LocalPrefixWait(),
	)
	log.Printf("masque connect_ip bootstrap: wait policy profile_local=%v require_prefix=%v first_wait=%s request_addresses=%v request_timeout=%s second_wait=%s advertise_profile_local=%v tag=%s",
		policy.ProfileLocal,
		policy.RequirePrefix,
		PrefixWaitLogValue(policy.FirstWait),
		policy.SendRequestAddresses,
		PrefixWaitLogValue(policy.RequestAddressesTimeout),
		PrefixWaitLogValue(policy.SecondWait),
		policy.AdvertiseProfileLocal,
		tag,
	)
	prefixes, errLP := WaitForNonEmptyAssignedPrefixes(conn, policy.FirstWait)
	if len(prefixes) == 0 && policy.SendRequestAddresses {
		initCtx, cancel := context.WithTimeout(context.Background(), policy.RequestAddressesTimeout)
		var requested []cip.RequestedAddress
		errReq := conn.RequestAddresses(initCtx, requested)
		cancel()
		if errReq != nil {
			_ = conn.Close()
			return fmt.Errorf("warp masque connect-ip initial RequestAddresses(empty): %w", errReq)
		}
		log.Printf("masque connect_ip bootstrap: cf-connect-ip initial RequestAddresses(empty) ok tag=%s (usque parity: empty ADDRESS_REQUEST)", tag)
		if policy.SecondWait > 0 {
			prefixes, errLP = WaitForNonEmptyAssignedPrefixes(conn, policy.SecondWait)
		}
	}

	// Require non-empty ADDRESS_ASSIGN before dataplane so gVisor local IP matches WARP egress;
	// synthetic 198.18.0.1 breaks return-path delivery to the TCP stack.
	if len(prefixes) == 0 {
		if !policy.RequirePrefix {
			log.Printf("masque connect_ip bootstrap: no assigned prefixes after passive+request waits (continuing; edge may assign later; netstack still waits LocalPrefixes) tag=%s err=%v", tag, errLP)
			if policy.AdvertiseProfileLocal {
				maybeAdvertiseProfileLocalRoutes(conn, p)
			}
			return nil
		}
		_ = conn.Close()
		if errLP != nil {
			return fmt.Errorf("warp masque connect-ip no assigned prefixes after bootstrap (ADDRESS_ASSIGN): %w", errLP)
		}
		return fmt.Errorf("warp masque connect-ip no assigned prefixes after bootstrap within %s", policy.FirstWait+policy.SecondWait)
	}
	log.Printf("masque connect_ip bootstrap: assigned prefix count=%d tag=%s", len(prefixes), tag)
	return nil
}

// GenericServerBootstrap waits briefly for ADDRESS_ASSIGN from a generic MASQUE server
// (AssignAddresses on the server side) so CONNECT-IP TCP netstack uses the same local as the wire.
func GenericServerBootstrap(conn BootstrapConn, p SessionBootstrapParams) error {
	if conn == nil || strings.TrimSpace(p.WarpConnectIPProtocol) != "" {
		return nil
	}
	tag := strings.TrimSpace(p.Tag)
	profileV4 := strings.TrimSpace(p.ProfileLocalIPv4)
	profileV6 := strings.TrimSpace(p.ProfileLocalIPv6)
	wait := SessionPrefixWait(profileV4, profileV6)
	if wait > 5*time.Second {
		wait = 5 * time.Second
	}
	prefixes, err := WaitForNonEmptyAssignedPrefixes(conn, wait)
	if len(prefixes) == 0 {
		if err != nil {
			log.Printf("masque connect_ip bootstrap: generic server no ADDRESS_ASSIGN within %s tag=%s err=%v", wait, tag, err)
		}
		return nil
	}
	log.Printf("masque connect_ip bootstrap: generic server assigned prefix count=%d tag=%s", len(prefixes), tag)
	return nil
}
