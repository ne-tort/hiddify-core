package masque

import strm "github.com/sagernet/sing-box/transport/masque/stream"

// ArchREFSRCUsqueRow documents one usque CONNECT-IP attribute vs sing-box connect_ip adapter (REF-SRC-USQUE).
type ArchREFSRCUsqueRow struct {
	ID       string
	Usque    string
	SB       string
	Portable bool
}

// ArchREFSRCUsqueAudit is the frozen REF-SRC-USQUE differential: usque MaintainTunnel vs connectip/netstack.go.
var ArchREFSRCUsqueAudit = []ArchREFSRCUsqueRow{
	{
		ID: "REF-SRC-USQUE-1", Usque: "Dial cf-connect-ip / packet tunnel",
		SB: "connect_ip template + Netstack egress WritePacket", Portable: false,
	},
	{
		ID: "REF-SRC-USQUE-2-dataplane", Usque: "ReadPacket/WritePacket datagram pump",
		SB: "gVisor netstack TCP over CONNECT-IP", Portable: false,
	},
	{
		ID: "REF-SRC-USQUE-2-maintain", Usque: "MaintainTunnel loop",
		SB: "connectip session bridge + packet handler", Portable: false,
	},
	{
		ID: "REF-SRC-USQUE-2-cfproto", Usque: "cf-connect-ip protocol",
		SB: "not CONNECT-stream tcp_transport", Portable: false,
	},
	{
		ID: "REF-SRC-USQUE-3-buffer", Usque: "packetBufferPool CloneInboundFrame",
		SB: "netstackInboundBufPool + CloneInboundFrame", Portable: true,
	},
	{
		ID: "REF-SRC-USQUE-3-relay", Usque: "TCP relay via userspace stack",
		SB: "stream/relay RelayTunnelBufLen 256 KiB (hybrid leg only)", Portable: true,
	},
}

// ArchREFSRCUsqueSourceNeedles are frozen substrings in connectip/netstack.go (embed audit).
var ArchREFSRCUsqueSourceNeedles = []string{
	"netstackInboundBufPool",
	"netstackOutboundBufPool",
	"CloneInboundFrame",
	"returnOutboundBuf",
	"WritePacket",
}

// ArchREFSRCUsqueRelayBufLen returns frozen relay buffer size for cross-package audit tests.
func ArchREFSRCUsqueRelayBufLen() int { return strm.RelayTunnelBufLen }

// ArchREFSRCUsqueScopeVerdict is the frozen REF-SRC-USQUE scope conclusion.
func ArchREFSRCUsqueScopeVerdict() string {
	return "CONNECT-IP packet plane non-portable to CONNECT-stream; buffer pools + relay buf portable"
}
