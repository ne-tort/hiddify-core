package masque

import (
	strm "github.com/sagernet/sing-box/transport/masque/stream"
)

// ArchREFSRCUsqueRow documents one usque attribute vs sing-box dataplane (REF-SRC-USQUE).
type ArchREFSRCUsqueRow struct {
	ID       string
	Usque    string
	SB       string
	Portable bool // true when pattern already exists on connect-stream or connect-ip path
	Anchor   string
	KPINote  string
}

// ArchREFSRCUsqueAudit is frozen REF-SRC-USQUE-1/2/3: usque CONNECT-IP scope vs connect-stream KPI path.
var ArchREFSRCUsqueAudit = []ArchREFSRCUsqueRow{
	{
		ID: "REF-SRC-USQUE-1",
		Usque: "TCP via gVisor netstack on TUN; tunnel = connectip.Dial(:protocol=cf-connect-ip); no CONNECT-stream bidi",
		SB:    "warp_masque: transport_mode=connect_ip, dialConnectIPTCP, cf-connect-ip only to CF edge",
		Portable: false,
		Anchor: "experiments/router/stand/usque/upstream/api/masque.go:ConnectTunnel; protocol/masque/endpoint_warp_masque.go",
		KPINote: "CONFIRMED: usque TCP is CONNECT-IP datagram plane, not HTTP/3 CONNECT-stream; K-S1/K-S2 unrelated",
	},
	{
		ID: "REF-SRC-USQUE-2-dataplane",
		Usque: "Packet plane: TUN↔connectip.Conn WritePacket/ReadPacket (RFC 9484 DATAGRAM)",
		SB:    "connectip/netstack.go gVisor stack; connect_stream uses strm.RelayTCPTunnel bidi HTTP/3",
		Portable: false,
		Anchor: "connectip/netstack.go; stream/relay.go:RelayTCPTunnel",
		KPINote: "Cannot port to connect-stream without full dataplane swap (CONNECT-IP ≠ template_tcp)",
	},
	{
		ID: "REF-SRC-USQUE-2-maintain",
		Usque: "MaintainTunnel: reconnect loop, dual TUN↔IP pumps, OnConnect/OnDisconnect hooks",
		SB:    "Per-session CONNECT-stream relay; connectip session lifecycle in connectip/dial_*.go",
		Portable: false,
		Anchor: "experiments/router/stand/usque/upstream/api/tunnel.go:MaintainTunnel",
		KPINote: "Tunnel maintain is client-edge WARP scope; not K-REF-B server relay fix",
	},
	{
		ID: "REF-SRC-USQUE-2-cfproto",
		Usque: ":protocol cf-connect-ip + SETTINGS 0x276 + mTLS device cert to cloudflareaccess.com",
		SB:    "WarpConnectIPProtocol=cf-connect-ip; CONNECT-stream to self-hosted s-ui uses template_tcp",
		Portable: false,
		Anchor: "endpoint_warp_masque.go; h3/quic_config.go:WarpCloudflareQUICBase",
		KPINote: "WARP consumer forbids CONNECT-stream to edge (403); prod K-REF-B is s-ui template_tcp",
	},
	{
		ID: "REF-SRC-USQUE-3-buffer",
		Usque: "NetBuffer sync.Pool (MTU-sized) for TUN pump loops in MaintainTunnel",
		SB:    "connectip: netstack{Outbound,Inbound}BufPool (~1600 B); connect-stream: relayTunnelBufPool 64 KiB io.CopyBuffer",
		Portable: true,
		Anchor: "connectip/netstack.go; stream/relay.go:relayTunnelCopyBuffer",
		KPINote: "Buffer pool pattern already adopted; no further port needed for K-REF-B",
	},
	{
		ID: "REF-SRC-USQUE-3-relay",
		Usque: "No server TCP relay — edge terminates CONNECT-IP; local TCP via netstack",
		SB:    "Server relay strm.RelayTCPTunnel (h2o parity); KPI gap = client S2C WINDOW not buffer pool",
		Portable: true,
		Anchor: "stream/relay.go:RelayTunnelBufLen=65536",
		KPINote: "usque Mbps reference is CONNECT-IP dataplane; connect-stream fix = eager WINDOW + wake (L2/L1b)",
	},
}

// ArchREFSRCUsqueRelayBufLen returns frozen connect-stream relay buffer for cross-package audit.
func ArchREFSRCUsqueRelayBufLen() int { return strm.RelayTunnelBufLen }

// ArchREFSRCUsqueScopeVerdict summarizes REF5 boundary for agents.
func ArchREFSRCUsqueScopeVerdict() string {
	return "usque TCP=CONNECT-IP only; MaintainTunnel/cf-connect-ip not portable to connect-stream; buffer pools already in connectip+stream"
}
