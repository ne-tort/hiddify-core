package connectip

import (
	"time"
)

const (
	bootstrapMinPrefixWait        = 20 * time.Second
	bootstrapFirstWaitCap         = 10 * time.Second
	bootstrapRelaxedSecondCap     = 6 * time.Second
	bootstrapFastRequestTimeout   = 5 * time.Second
	bootstrapNormalRequestTimeout = 30 * time.Second
)

// BootstrapWaitPolicy drives CONNECT-IP ADDRESS_ASSIGN bootstrap waits.
type BootstrapWaitPolicy struct {
	ProfileLocal            bool
	RequirePrefix           bool
	FirstWait               time.Duration
	SendRequestAddresses    bool
	RequestAddressesTimeout time.Duration
	SecondWait              time.Duration
	AdvertiseProfileLocal   bool
}

// NewBootstrapWaitPolicy builds prefix/bootstrap wait timings for CONNECT-IP session open.
func NewBootstrapWaitPolicy(requirePrefix bool, profileLocalIPv4 string, profileLocalIPv6 string, baseWait time.Duration) BootstrapWaitPolicy {
	profileLocal := HasBootstrapProfileLocal(profileLocalIPv4, profileLocalIPv6)
	if !requirePrefix && profileLocal {
		sessionWait := SessionPrefixWait(profileLocalIPv4, profileLocalIPv6)
		return BootstrapWaitPolicy{
			ProfileLocal:            true,
			RequirePrefix:           false,
			FirstWait:               sessionWait,
			SendRequestAddresses:    true,
			RequestAddressesTimeout: bootstrapFastRequestTimeout,
			SecondWait:              sessionWait,
			AdvertiseProfileLocal:   true,
		}
	}

	wait := baseWait
	if wait < bootstrapMinPrefixWait {
		wait = bootstrapMinPrefixWait
	}
	firstWait := wait
	if firstWait > bootstrapFirstWaitCap {
		firstWait = bootstrapFirstWaitCap
	}
	secondWait := wait
	if !requirePrefix && secondWait > bootstrapRelaxedSecondCap {
		secondWait = bootstrapRelaxedSecondCap
	}
	return BootstrapWaitPolicy{
		ProfileLocal:            profileLocal,
		RequirePrefix:           requirePrefix,
		FirstWait:               firstWait,
		SendRequestAddresses:    true,
		RequestAddressesTimeout: bootstrapNormalRequestTimeout,
		SecondWait:              secondWait,
		AdvertiseProfileLocal:   !requirePrefix && profileLocal,
	}
}

// HasBootstrapProfileLocal reports whether profile tunnel-local fields are usable.
func HasBootstrapProfileLocal(profileLocalIPv4 string, profileLocalIPv6 string) bool {
	v4 := ParseProfileInterfaceAddress(profileLocalIPv4)
	if v4.Is4() {
		return true
	}
	v6 := ParseProfileInterfaceAddress(profileLocalIPv6)
	return v6.Is6() && !v6.Is4In6()
}

// LegacyH2BootstrapPolicy builds passive prefix/bootstrap waits for CONNECT-IP over HTTP/2
// without RFC 9484 control capsules (no RequestAddresses / AdvertiseRoute on the wire).
func LegacyH2BootstrapPolicy(requirePrefix bool, profileLocalIPv4 string, profileLocalIPv6 string) BootstrapWaitPolicy {
	policy := NewBootstrapWaitPolicy(requirePrefix, profileLocalIPv4, profileLocalIPv6, LocalPrefixWait())
	policy.SendRequestAddresses = false
	policy.RequestAddressesTimeout = 0
	return policy
}

// genericServerBootstrapPolicy builds ADDRESS_ASSIGN waits for non-WARP CONNECT-IP servers.
// Self-hosted servers (connectip/handler.go) call AssignAddresses unprompted on CONNECT;
// sending an empty ADDRESS_REQUEST makes a strict RFC peer abort the stream (IP-25 §4.7.2).
func genericServerBootstrapPolicy(profileLocalIPv4, profileLocalIPv6 string, controlCapsules bool) BootstrapWaitPolicy {
	if !controlCapsules {
		return LegacyH2BootstrapPolicy(false, profileLocalIPv4, profileLocalIPv6)
	}
	policy := NewBootstrapWaitPolicy(false, profileLocalIPv4, profileLocalIPv6, LocalPrefixWait())
	policy.SendRequestAddresses = false
	policy.RequestAddressesTimeout = 0
	if !HasBootstrapProfileLocal(profileLocalIPv4, profileLocalIPv6) {
		const genericPassiveWait = 500 * time.Millisecond
		if policy.FirstWait > genericPassiveWait {
			policy.FirstWait = genericPassiveWait
		}
	}
	return policy
}

// PrefixWaitLogValue formats a wait duration for bootstrap logs.
func PrefixWaitLogValue(d time.Duration) string {
	if d <= 0 {
		return "0s"
	}
	return d.String()
}
