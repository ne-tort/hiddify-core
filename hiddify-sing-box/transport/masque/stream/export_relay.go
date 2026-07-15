package stream

import "github.com/sagernet/sing-box/transport/masque/stream/relay"

type RelayCONNECTH3Leg = relay.RelayCONNECTH3Leg

type RelayTCPPolicy = relay.RelayTCPPolicy

const (
	RelayTunnelBufLen     = relay.RelayTunnelBufLen
	RelayTunnelFlushBytes = relay.RelayTunnelFlushBytes
)

var (
	RelayTCPTunnel               = relay.RelayTCPTunnel
	RelayTCPTunnelBidiStream     = relay.RelayTCPTunnelBidiStream
	RelayTunnelDownloadH2        = relay.RelayTunnelDownloadH2
	RelayUseHTTP3StreamHijack    = relay.RelayUseHTTP3StreamHijack
	CurrentRelayTCPPolicy        = relay.CurrentRelayTCPPolicy
	StripH2ClientBootstrapUpload = relay.StripH2ClientBootstrapUpload
	ReplayH2BootstrapUpload      = relay.ReplayH2BootstrapUpload
)
