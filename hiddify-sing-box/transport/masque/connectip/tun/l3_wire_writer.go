package tun

// writeWirePacket sends one datagram to CONNECT-IP wire (usque ipConn.WritePacket parity).
func writeWirePacket(writer PacketWriter, p []byte) ([]byte, error) {
	return writer.WritePacket(p)
}

// writeWirePacketNoWake enqueues without transport flush; caller must FlushEgressBatch once per LoopIn iter.
func writeWirePacketNoWake(writer PacketWriter, p []byte) ([]byte, error) {
	if nw, ok := writer.(interface {
		WritePacketNoWake([]byte) ([]byte, error)
	}); ok {
		return nw.WritePacketNoWake(p)
	}
	return writeWirePacket(writer, p)
}

// writeWirePacketInPlaceNoWake enqueues caller-owned buffer without copy when supported.
func writeWirePacketInPlaceNoWake(writer PacketWriter, p []byte) (retained bool, icmp []byte, err error) {
	if ip, ok := writer.(interface {
		WritePacketInPlaceNoWake([]byte) (bool, []byte, error)
	}); ok {
		return ip.WritePacketInPlaceNoWake(p)
	}
	icmp, err = writeWirePacketNoWake(writer, p)
	return false, icmp, err
}
