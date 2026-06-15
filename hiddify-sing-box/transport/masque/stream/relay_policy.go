package stream

// RelayTCPMode names the server-side CONNECT-stream relay dataplane.
type RelayTCPMode string

const (
	RelayTCPModeH3StreamHijack RelayTCPMode = "h3_stream_hijack"
)

// RelayTCPPolicy captures the server relay mode and CONNECT-stream leg role.
type RelayTCPPolicy struct {
	Mode    RelayTCPMode
	LegRole string
}

// CurrentRelayTCPPolicy reports the prod relay policy (h2o hijack + batched duplex wake).
func CurrentRelayTCPPolicy(legRole string) RelayTCPPolicy {
	return RelayTCPPolicy{
		Mode:    RelayTCPModeH3StreamHijack,
		LegRole: legRole,
	}
}

func (p RelayTCPPolicy) IsSplitDownloadLeg() bool {
	return p.LegRole == ConnectStreamLegDownload
}

func (p RelayTCPPolicy) IsSplitUploadLeg() bool {
	return p.LegRole == ConnectStreamLegUpload
}

// UseHijackRelay selects hijacked *http3.Stream relay (prod always on).
func (p RelayTCPPolicy) UseHijackRelay() bool {
	return true
}

// UseSchedulerBoost off — server download-active starves client C2S without bidi send boost.
func (p RelayTCPPolicy) UseSchedulerBoost() bool {
	return false
}

// UsePerChunkWake enables MasqueWakeBidiDuplex after each copy chunk (prod off).
func (p RelayTCPPolicy) UsePerChunkWake() bool {
	return false
}

// UseBatchedDuplexWake off — h2o proxy.tunnel uses plain io.CopyBuffer without QUIC poke.
func (p RelayTCPPolicy) UseBatchedDuplexWake() bool {
	return false
}
