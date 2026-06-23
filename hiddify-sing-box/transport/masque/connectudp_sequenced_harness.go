package masque

import (
	"net"
	"testing"

	"github.com/sagernet/sing-box/transport/masque/connectudp"
)

// runUDPSequencedSink listens for sequenced probes (docker udp_sink parity).
func runUDPSequencedSink(tb testing.TB, addr *net.UDPAddr, runID uint32) (*net.UDPConn, *connectudp.SequencedSink) {
	tb.Helper()
	c, err := net.ListenUDP("udp", addr)
	if err != nil {
		tb.Fatalf("listen sequenced sink udp: %v", err)
	}
	tb.Cleanup(func() { _ = c.Close() })
	tuneSequencedSinkSocket(c)
	sink := connectudp.NewSequencedSink(runID)
	go func() {
		buf := make([]byte, 2048)
		for {
			n, _, err := c.ReadFrom(buf)
			if err != nil {
				return
			}
			if n > 0 {
				sink.Record(buf[:n])
			}
		}
	}()
	return c, sink
}

func tuneSequencedSinkSocket(c *net.UDPConn) {
	const buf = 4 << 20
	_ = c.SetReadBuffer(buf)
	_ = c.SetWriteBuffer(buf)
}
