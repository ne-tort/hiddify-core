package quic

import "sync/atomic"

var packetReceiveDropConnQueueFull atomic.Uint64
var packetReceiveDropServerQueueFull atomic.Uint64

// PacketReceiveDropPathBreakdown counts QUIC UDP datagram drops before short-header decrypt,
// due to capped receive queues (DOS-prevention thresholds in Conn.handlePacket / baseServer.handlePacket).
//
// Keys:
//   - conn_queue_full_drop: Conn.receivedPackets already at protocol.MaxConnUnprocessedPackets (256).
//   - server_queue_full_drop: baseServer.receivedPackets channel full (protocol.MaxServerUnprocessedPackets, 1024).
func PacketReceiveDropPathBreakdown() map[string]uint64 {
	return map[string]uint64{
		"conn_queue_full_drop":      packetReceiveDropConnQueueFull.Load(),
		"server_queue_full_drop":    packetReceiveDropServerQueueFull.Load(),
	}
}

func incrementPacketReceiveDropConnQueueFull() {
	packetReceiveDropConnQueueFull.Add(1)
}

func incrementPacketReceiveDropServerQueueFull() {
	packetReceiveDropServerQueueFull.Add(1)
}
