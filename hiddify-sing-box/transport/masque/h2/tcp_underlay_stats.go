package h2

import "github.com/sagernet/sing-box/transport/masque/netutil"

// TCPUnderlayStats is the always-on MASQUE H2 TLS-underlay TCP_INFO aggregate.
type TCPUnderlayStats = netutil.TCPUnderlayStatsSnapshot

// SnapshotTCPUnderlayStats returns underlay loss/retrans/cwnd/RWND for benches.
// Prefer this over iperf Retr inside the tunnel — VPN TCP retrans often invisible there.
func SnapshotTCPUnderlayStats() TCPUnderlayStats {
	return netutil.SnapshotTCPUnderlayStats()
}
