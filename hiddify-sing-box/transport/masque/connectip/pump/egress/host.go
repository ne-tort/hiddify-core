package egress

// PacketConn is the connect-ip-go proxied IP datagram write surface used by egress.
type PacketConn interface {
	WritePacket(buffer []byte) (icmp []byte, err error)
	WritePacketNoWake(buffer []byte) (icmp []byte, err error)
	WritePacketInPlaceNoWake(outbound []byte) (icmp []byte, retained bool, err error)
	FlushOutgoingDatagramSend()
}

// ClientHost binds one CONNECT-IP client packet session for egress pump calls.
type ClientHost interface {
	PacketConn() PacketConn
	DatagramCeiling() int
	WakeAfterDatagram() func()
}
