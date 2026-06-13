package masque

import strm "github.com/sagernet/sing-box/transport/masque/stream"

// ArchH2OConnectConfPath is the frozen h2o reference config for REF2-1 audit.
const ArchH2OConnectConfPath = "docker/masque-vps-bench/h2o/connect.conf"

// ArchH2OParityRow documents one h2o proxy.tunnel attribute vs sing-box RelayTCPTunnel (REF2-1).
type ArchH2OParityRow struct {
	Attr       string
	H2OValue   string
	SBValue    string
	Parity     bool
	Anchor     string
	KPINote    string
}

// ArchH2OParityAudit is the frozen REF2-1 differential: h2o connect.conf vs stream/relay.go.
var ArchH2OParityAudit = []ArchH2OParityRow{
	{
		Attr: "proxy.tunnel", H2OValue: "ON", SBValue: "RelayTCPTunnel default (2×io.CopyBuffer goroutines)",
		Parity: true, Anchor: "transport/masque/stream/relay.go:RelayTCPTunnel",
		KPINote: "full-duplex tunnel; ceiling is wire FC not relay shape",
	},
	{
		Attr: "proxy.max-buffer-size", H2OValue: "65536", SBValue: "RelayTunnelBufLen=65536",
		Parity: true, Anchor: "transport/masque/stream/relay.go:RelayTunnelBufLen",
		KPINote: "H2/H3 copy buffer matches h2o",
	},
	{
		Attr: "H2 response flush batch", H2OValue: "implicit (tunnel)", SBValue: "RelayTunnelFlushBytes=65536",
		Parity: true, Anchor: "transport/masque/stream/relay.go:relayTunnelFlushWriter",
		KPINote: "was 32 KiB; aligned 2026-06-13",
	},
	{
		Attr: "H2 download bulk copy", H2OValue: "tunnel io.Copy", SBValue: "io.CopyBuffer after prime",
		Parity: true, Anchor: "transport/masque/stream/relay.go:relayTunnelDownloadRelay",
		KPINote: "replaces per-read loop; interleave via goroutine split unchanged",
	},
	{
		Attr: "H3 hijack path", H2OValue: "native QUIC stream", SBValue: "relayTCPTunnelBidiStream io.CopyBuffer",
		Parity: true, Anchor: "transport/masque/stream/relay.go:relayTCPTunnelBidiStream",
		KPINote: "prod H3 path; windowed ~14.8 Mbit/s = peer FC",
	},
}

// ArchH2OParityRelayBufLen returns frozen copy-buffer size for cross-package audit tests.
func ArchH2OParityRelayBufLen() int { return strm.RelayTunnelBufLen }

// ArchH2OParityRelayFlushBytes returns frozen H2 flush batch for cross-package audit tests.
func ArchH2OParityRelayFlushBytes() int { return strm.RelayTunnelFlushBytes }

// ArchEndpointRelayRow documents one server entry path vs shared relay.TCPTunnel (REF2-5).
type ArchEndpointRelayRow struct {
	Path     string
	RelayFn  string
	Delegate string
	Parity   bool
	Note     string
}

// ArchEndpointRelayAudit is the frozen REF2-5 differential: template / authority / endpoint → relay.
var ArchEndpointRelayAudit = []ArchEndpointRelayRow{
	{
		Path: "server/connect_stream.go (template)", RelayFn: "relay.TCPForward",
		Delegate: "relay.TCPTunnel → RelayTCPTunnel", Parity: true,
		Note: "s-ui template tcp_relay=template; mux BuildMuxHandler tcpPath",
	},
	{
		Path: "server/connect_authority_relay.go (authority)", RelayFn: "relay.TCPTunnel",
		Delegate: "strm.RelayTCPTunnel", Parity: true,
		Note: "thin/Invisv CONNECT https://host:port/; tcp_relay=authority",
	},
	{
		Path: "protocol/masque/endpoint_server.go", RelayFn: "server.HandleTCPConnectRequest",
		Delegate: "no alternate relay in endpoint adapter", Parity: true,
		Note: "ServerEndpoint.handleTCPConnectRequest thin wrapper only",
	},
}
