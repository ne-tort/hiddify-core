package relay

// RelayTCPPolicy is the prod h2o/Invisv CONNECT-stream relay policy (single bidi hijack + plain copy).
type RelayTCPPolicy struct{}

// CurrentRelayTCPPolicy reports the prod relay policy.
func CurrentRelayTCPPolicy(string) RelayTCPPolicy {
	return RelayTCPPolicy{}
}

// RelayUseHTTP3StreamHijack enables hijacked HTTP/3 stream relay (prod always on).
func RelayUseHTTP3StreamHijack() bool { return true }

// RelayUploadFromStream reads client upload from the hijacked HTTP/3 stream (prod always on).
func RelayUploadFromStream() bool { return true }
