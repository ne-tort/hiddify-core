package netstack

// PacketSession is the CONNECT-IP unreliable packet plane (ReadPacket / WritePacket).
type PacketSession interface {
	ReadPacket(buffer []byte) (int, error)
	WritePacket(buffer []byte) (icmp []byte, err error)
	Close() error
}

// PacketWriteTransferSession accepts netstack outbound pool buffer ownership on WritePacket.
type PacketWriteTransferSession interface {
	PacketSession
	WritePacketFromNetstack(outbound []byte) (retained bool, icmp []byte, err error)
}
