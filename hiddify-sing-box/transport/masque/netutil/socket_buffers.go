package netutil

// MasqueSocketBufferBytes is the kernel snd/rcv buffer size for MASQUE onward sockets.
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

// TuneMasqueTCPSocketBuffers sets bulk snd/rcv buffers on MASQUE H2 TLS underlay.
// Nagle on (NoDelay false) coalesces small TLS records into fewer TCP segments (upload goodput).
func TuneMasqueTCPSocketBuffers(conn bufferConn) {
	TuneMasqueUDPSocketBuffers(conn)
	if tc, ok := conn.(interface{ SetNoDelay(bool) error }); ok {
		_ = tc.SetNoDelay(false)
	}
}
