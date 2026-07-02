package relay

import (
	"fmt"
	"strings"
	"sync/atomic"

	"github.com/sagernet/sing-box/transport/masque/connectudp/frame"
)

// ProdRelayMaxUDPPayloadBytes is the default server relay onward cap (Ethernet-ish MTU).
const ProdRelayMaxUDPPayloadBytes = 1500

// RelayPayloadPolicy selects CONNECT-UDP server relay MTU cap (UDP-RFC-DEV-02).
type RelayPayloadPolicy uint32

const (
	// RelayPayloadProd silently drops proxied UDP larger than ProdRelayMaxUDPPayloadBytes.
	RelayPayloadProd RelayPayloadPolicy = iota
	// RelayPayloadRFCInterop allows RFC 9298 legal payloads up to 65527 bytes through relay.
	RelayPayloadRFCInterop
)

const (
	// RelayPayloadConfigProd is the JSON value for prod relay cap (1500 B).
	RelayPayloadConfigProd = "prod"
	// RelayPayloadConfigRFCInterop is the JSON value for RFC interop relay cap (65527 B).
	RelayPayloadConfigRFCInterop = "rfc_interop"
)

var relayPayloadPolicy atomic.Uint32

func init() {
	relayPayloadPolicy.Store(uint32(RelayPayloadProd))
}

// SetRelayPayloadPolicy sets process-wide relay MTU policy (server startup or interop harness).
func SetRelayPayloadPolicy(p RelayPayloadPolicy) {
	relayPayloadPolicy.Store(uint32(p))
}

// RelayPayloadPolicyCurrent returns the active relay MTU policy.
func RelayPayloadPolicyCurrent() RelayPayloadPolicy {
	return RelayPayloadPolicy(relayPayloadPolicy.Load())
}

// RelayMaxUDPPayloadBytes returns the active relay cap for proxied UDP payloads.
func RelayMaxUDPPayloadBytes() int {
	if RelayPayloadPolicyCurrent() == RelayPayloadRFCInterop {
		return frame.MaxProxiedUDPPayloadBytes
	}
	return ProdRelayMaxUDPPayloadBytes
}

// relayExceedsMTUCap reports whether payloadLen should be dropped before onward relay.
func relayExceedsMTUCap(payloadLen int) bool {
	return payloadLen > RelayMaxUDPPayloadBytes()
}

// ParseRelayPayloadPolicyConfig maps endpoint JSON connect_udp_relay_payload_policy.
func ParseRelayPayloadPolicyConfig(policy string) (RelayPayloadPolicy, error) {
	switch strings.ToLower(strings.TrimSpace(policy)) {
	case "", RelayPayloadConfigProd:
		return RelayPayloadProd, nil
	case RelayPayloadConfigRFCInterop:
		return RelayPayloadRFCInterop, nil
	default:
		return RelayPayloadProd, fmt.Errorf("unknown connect_udp_relay_payload_policy %q (want %q or %q)",
			policy, RelayPayloadConfigProd, RelayPayloadConfigRFCInterop)
	}
}

// ConfigureRelayPayloadPolicyFromConfig applies server endpoint policy (process-wide).
func ConfigureRelayPayloadPolicyFromConfig(policy string) error {
	p, err := ParseRelayPayloadPolicyConfig(policy)
	if err != nil {
		return err
	}
	SetRelayPayloadPolicy(p)
	return nil
}
