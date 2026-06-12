package relay

import "net"

// TuneTCPOutbound applies best-effort kernel buffer tuning on onward TCP dials.
func TuneTCPOutbound(c net.Conn) {
	if tc, ok := c.(*net.TCPConn); ok {
		_ = tc.SetNoDelay(true)
		_ = tc.SetReadBuffer(TCPKernelBuf)
		_ = tc.SetWriteBuffer(TCPKernelBuf)
	}
}
