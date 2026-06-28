package tun

// writeWirePacket sends one datagram to CONNECT-IP wire (usque ipConn.WritePacket parity).
func writeWirePacket(writer PacketWriter, p []byte) ([]byte, error) {
	return writer.WritePacket(p)
}
