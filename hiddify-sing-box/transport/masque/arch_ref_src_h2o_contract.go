//go:build masque_arch_ledger

package masque

// ArchREFSRCH2oAudit — frozen h2o proxy.tunnel relay contract (Invisv testdata/h2o/connect.conf parity in stream/relay.go).
var ArchREFSRCH2oAudit = []string{
	"RelayTunnelBufLen = 256 * 1024",
	"RelayTunnelFlushBytes = RelayTunnelBufLen",
	"RelayTCPTunnel",
	"io.CopyBuffer",
	"relayTCPTunnelBidiStream",
}

// ArchREFSRCH2oConnectConfNeedles are frozen strings from Invisv testdata/h2o/connect.conf (not in relay.go embed).
var ArchREFSRCH2oConnectConfNeedles = []string{
	"proxy.max-buffer-size: 65536",
	"proxy.tunnel",
}
