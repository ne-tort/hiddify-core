package netutil

// MasqueSocketBufferBytes is the kernel snd/rcv target for MASQUE bulk sockets.
const MasqueSocketBufferBytes = 4 << 20

type bufferConn interface {
	SetReadBuffer(int) error
	SetWriteBuffer(int) error
}

// TuneMasqueUDPSocketBuffers sets 4 MiB kernel UDP buffers (H2+H3 server onward dial parity).
func TuneMasqueUDPSocketBuffers(conn bufferConn) {
	if conn == nil {
		return
	}
	_ = conn.SetReadBuffer(MasqueSocketBufferBytes)
	_ = conn.SetWriteBuffer(MasqueSocketBufferBytes)
}

// TuneMasqueTCPSocketBuffers tunes the MASQUE H2 TLS underlay.
//
// Do NOT SetReadBuffer on Linux TCP: SO_RCVBUF locks SOCK_RCVBUF_LOCK and can leave
// rcv_ssthresh ≈32 KiB on WAN (~8 Mbit @30 ms) despite skmem rb=8 MiB. Rely on
// tcp_rmem auto-tune for receive; only lock SO_SNDBUF (+ Nagle-on) for send bulk.
func TuneMasqueTCPSocketBuffers(conn bufferConn) {
	if conn == nil {
		return
	}
	_ = conn.SetWriteBuffer(MasqueSocketBufferBytes)
	if tc, ok := conn.(interface{ SetNoDelay(bool) error }); ok {
		_ = tc.SetNoDelay(false)
	}
}
