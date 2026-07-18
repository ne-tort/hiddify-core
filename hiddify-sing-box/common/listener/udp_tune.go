package listener

import "net"

// UDPAssociateSocketBuf is the kernel SO_RCVBUF/SO_SNDBUF for SOCKS5 UDP ASSOCIATE
// ephemeral sockets. Default Linux ~212 KiB silently drops under paced MASQUE upload
// while copyPacketUpload blocks in WriteTo (cross H2@50 ≈1.7% = RcvbufErrors).
//
// At ~500 Mbit paced H3, WriteTo soft-backpressure (conn h3C2SSendBacklogSoftLimit) can
// stall briefly; 4 MiB ≈ 64 ms and still overflowed under SOCKS microburst before soft limit.
// 16 MiB ≈ 250 ms @500 Mbit — headroom while soft limit keeps QUIC send queue shallow.
//
// Docker Desktop / some containers cap net.core.rmem_max ≈212 KiB and omit the sysctl node;
// plain SetReadBuffer then silently sticks at ~426 KiB (getsockopt×2). Linux path uses
// SO_RCVBUFFORCE/SO_SNDBUFFORCE when CAP_NET_ADMIN is present (compose client is privileged).
const UDPAssociateSocketBuf = 16 << 20

// TuneUDPSocketBuffers raises UDP snd/rcv buffers when pc is a *net.UDPConn.
func TuneUDPSocketBuffers(pc net.PacketConn) {
	uc, ok := pc.(*net.UDPConn)
	if !ok {
		return
	}
	tuneUDPSocketBuffers(uc)
}
