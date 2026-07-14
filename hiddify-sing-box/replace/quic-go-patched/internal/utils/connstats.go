package utils

import "sync/atomic"

// ConnectionStats stores stats for the connection. See the public
// ConnectionStats struct in connection.go for more information
type ConnectionStats struct {
	BytesSent       atomic.Uint64
	PacketsSent     atomic.Uint64
	BytesReceived   atomic.Uint64
	PacketsReceived atomic.Uint64
	BytesLost       atomic.Uint64
	PacketsLost     atomic.Uint64
	// SpuriousPacketsLost counts packets previously declared lost that were later ACKed.
	// PacketsLost/BytesLost are decremented on that path (see detectSpuriousLosses).
	SpuriousPacketsLost atomic.Uint64
}
