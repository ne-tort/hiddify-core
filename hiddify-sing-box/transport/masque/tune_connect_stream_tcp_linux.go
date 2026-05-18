//go:build linux

package masque

import (
	"io"
	"net"

	"github.com/sagernet/sing/common/control"
	"golang.org/x/sys/unix"
)

func setTCPQuickAck(tc *net.TCPConn) {
	_ = control.Conn(tc, func(fd uintptr) error {
		return unix.SetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_QUICKACK, 1)
	})
}

func tuneConnectStreamTCPRelayQuickAck(tc *net.TCPConn) {
	setTCPQuickAck(tc)
}

// WrapTCPQuickAckWriter re-enables TCP_QUICKACK after each Write on Linux so the relay socket
// keeps immediate-ACK mode on the receive side while download bulk is written (iperf -R).
func WrapTCPQuickAckWriter(c net.Conn, w io.Writer) io.Writer {
	tc := extractTCPConn(c)
	if tc == nil || w == nil {
		return w
	}
	return &tcpQuickAckWriter{Writer: w, tcp: tc}
}

type tcpQuickAckWriter struct {
	io.Writer
	tcp *net.TCPConn
}

func (w *tcpQuickAckWriter) UpstreamWriter() io.Writer {
	return w.Writer
}

func (w *tcpQuickAckWriter) Write(p []byte) (int, error) {
	n, err := w.Writer.Write(p)
	if n > 0 {
		setTCPQuickAck(w.tcp)
	}
	return n, err
}

// WrapTCPQuickAckReader re-enables TCP_QUICKACK after each Read on Linux so delayed-ACK on the
// inner TUN↔iperf leg does not clock MASQUE download at ~one segment per RTT (bench ~15 Mbit/s).
func WrapTCPQuickAckReader(c net.Conn) net.Conn {
	tc := extractTCPConn(c)
	if tc == nil {
		return c
	}
	return &tcpQuickAckReader{Conn: c, tcp: tc}
}

type tcpQuickAckReader struct {
	net.Conn
	tcp *net.TCPConn
}

func (r *tcpQuickAckReader) Read(p []byte) (int, error) {
	n, err := r.Conn.Read(p)
	if n > 0 {
		setTCPQuickAck(r.tcp)
	}
	return n, err
}
