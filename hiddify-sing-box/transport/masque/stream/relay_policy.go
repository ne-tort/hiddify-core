package stream

// RelayTCPPolicy is the prod h2o/Invisv CONNECT-stream relay policy (single bidi hijack + plain copy).
type RelayTCPPolicy struct{}

// CurrentRelayTCPPolicy reports the prod relay policy.
func CurrentRelayTCPPolicy(string) RelayTCPPolicy {
	return RelayTCPPolicy{}
}
