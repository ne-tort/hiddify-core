package masque

import (
	"time"
)

const (
	connectIPBootstrapMinPrefixWait        = 20 * time.Second
	connectIPBootstrapFirstWaitCap         = 10 * time.Second
	connectIPBootstrapRelaxedSecondCap     = 6 * time.Second
	connectIPBootstrapFastProfileWait      = 500 * time.Millisecond
	connectIPBootstrapFastRequestTimeout   = 5 * time.Second
	connectIPBootstrapNormalRequestTimeout = 30 * time.Second
)

type connectIPBootstrapWaitPolicy struct {
	ProfileLocal            bool
	RequirePrefix           bool
	FirstWait               time.Duration
	SendRequestAddresses    bool
	RequestAddressesTimeout time.Duration
	SecondWait              time.Duration
	AdvertiseProfileLocal   bool
}

func newConnectIPBootstrapWaitPolicy(requirePrefix bool, profileLocalIPv4 string, profileLocalIPv6 string, baseWait time.Duration) connectIPBootstrapWaitPolicy {
	profileLocal := hasConnectIPBootstrapProfileLocal(profileLocalIPv4, profileLocalIPv6)
	if !requirePrefix && profileLocal {
		return connectIPBootstrapWaitPolicy{
			ProfileLocal:            true,
			RequirePrefix:           false,
			FirstWait:               connectIPBootstrapFastProfileWait,
			SendRequestAddresses:    true,
			RequestAddressesTimeout: connectIPBootstrapFastRequestTimeout,
			SecondWait:              connectIPBootstrapFastProfileWait,
			AdvertiseProfileLocal:   true,
		}
	}

	wait := baseWait
	if wait < connectIPBootstrapMinPrefixWait {
		wait = connectIPBootstrapMinPrefixWait
	}
	firstWait := wait
	if firstWait > connectIPBootstrapFirstWaitCap {
		firstWait = connectIPBootstrapFirstWaitCap
	}
	secondWait := wait
	if !requirePrefix && secondWait > connectIPBootstrapRelaxedSecondCap {
		secondWait = connectIPBootstrapRelaxedSecondCap
	}
	return connectIPBootstrapWaitPolicy{
		ProfileLocal:            profileLocal,
		RequirePrefix:           requirePrefix,
		FirstWait:               firstWait,
		SendRequestAddresses:    true,
		RequestAddressesTimeout: connectIPBootstrapNormalRequestTimeout,
		SecondWait:              secondWait,
		AdvertiseProfileLocal:   !requirePrefix && profileLocal,
	}
}

func hasConnectIPBootstrapProfileLocal(profileLocalIPv4 string, profileLocalIPv6 string) bool {
	v4 := parseProfileInterfaceAddress(profileLocalIPv4)
	if v4.Is4() {
		return true
	}
	v6 := parseProfileInterfaceAddress(profileLocalIPv6)
	return v6.Is6() && !v6.Is4In6()
}

func prefixWaitLogValue(d time.Duration) string {
	if d <= 0 {
		return "0s"
	}
	return d.String()
}
