package server

import (
	"net"
	"os"
	"sync/atomic"
	"time"

	cip "github.com/sagernet/sing-box/transport/masque/connectip"
	fwd "github.com/sagernet/sing-box/transport/masque/forwarder"
	"github.com/sagernet/sing/common/buf"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// connectIPServerParseDropTotal counts inbound CONNECT-IP packets dropped at the
// server IP parse boundary (non-fatal; read continues).
var connectIPServerParseDropTotal atomic.Uint64

// ConnectIPServerParseDropTotal exposes the parse-drop counter for tests/ops.
func ConnectIPServerParseDropTotal() uint64 {
	return connectIPServerParseDropTotal.Load()
}

// ConnectIPMaxICMPRelay is the PTB/control feedback relay cap per WritePacket.
const ConnectIPMaxICMPRelay = 8

// ConnectIPMaxParseDropPerRead caps consecutive IP parse drops in ReadPacket/ReadFrom
// before fail-closed. Guards the UDP-bridge parse loop; TCP forwarder reads conn directly.
const ConnectIPMaxParseDropPerRead = 64

var errConnectIPParseDropCeiling = E.New("connect-ip: parse drop ceiling exceeded")

// ConnectIPNetPacketConn adapts connectip.Conn to sing N.PacketConn for server routing.
type ConnectIPNetPacketConn struct {
	Conn      fwd.PacketPlaneConn
	deadlines connDeadlines
}

var _ N.PacketConn = (*ConnectIPNetPacketConn)(nil)

// NewConnectIPNetPacketConn wraps a live CONNECT-IP packet plane session.
func NewConnectIPNetPacketConn(conn fwd.PacketPlaneConn) *ConnectIPNetPacketConn {
	return &ConnectIPNetPacketConn{Conn: conn}
}

func (c *ConnectIPNetPacketConn) ReadPacket(buffer *buf.Buffer) (destination M.Socksaddr, err error) {
	consecutiveDrops := 0
	for {
		n, err := c.Conn.ReadPacket(buffer.FreeBytes())
		if err != nil {
			cip.TrackReadExit(err)
			return M.Socksaddr{}, err
		}
		buffer.Truncate(n)
		destination, payloadStart, payloadEnd, parseErr := ParseIPDestinationAndPayload(buffer.Bytes())
		if parseErr != nil {
			connectIPServerParseDropTotal.Add(1)
			consecutiveDrops++
			if consecutiveDrops >= ConnectIPMaxParseDropPerRead {
				cip.TrackReadExit(errConnectIPParseDropCeiling)
				return M.Socksaddr{}, errConnectIPParseDropCeiling
			}
			buffer.Reset()
			if c.deadlines.readTimeoutExceeded() {
				return M.Socksaddr{}, os.ErrDeadlineExceeded
			}
			continue
		}
		if payloadStart > 0 || payloadEnd < n {
			buffer.Advance(payloadStart)
			buffer.Truncate(payloadEnd - payloadStart)
		}
		cip.TrackPacketRx(n)
		return destination, nil
	}
}

func (c *ConnectIPNetPacketConn) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	return c.writeOutgoingWithICMPRelay(buffer.Bytes())
}

func (c *ConnectIPNetPacketConn) writeOutgoingWithICMPRelay(packet []byte) error {
	peerPrefixes := c.Conn.CurrentPeerPrefixes()
	payload := fwd.RewriteOutgoingPeerDst(packet, peerPrefixes)
	for i := 0; i < ConnectIPMaxICMPRelay; i++ {
		if i > 0 {
			payload = fwd.RewriteOutgoingPeerDst(payload, peerPrefixes)
		}
		icmp, err := c.Conn.WritePacket(payload)
		cip.TrackServerWriteIteration(len(payload), len(icmp), err)
		if err != nil {
			return err
		}
		if len(icmp) == 0 {
			return nil
		}
		payload = icmp
	}
	return E.New("connect-ip: ICMP feedback relay exceeded")
}

func (c *ConnectIPNetPacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	if c.deadlines.readTimeoutExceeded() {
		return 0, nil, os.ErrDeadlineExceeded
	}
	consecutiveDrops := 0
	for {
		n, err = c.Conn.ReadPacket(p)
		if err != nil {
			cip.TrackReadExit(err)
			return 0, nil, err
		}
		rawN := n
		destination, payloadStart, payloadEnd, parseErr := ParseIPDestinationAndPayload(p[:n])
		if parseErr != nil {
			connectIPServerParseDropTotal.Add(1)
			consecutiveDrops++
			if consecutiveDrops >= ConnectIPMaxParseDropPerRead {
				cip.TrackReadExit(errConnectIPParseDropCeiling)
				return 0, nil, errConnectIPParseDropCeiling
			}
			if c.deadlines.readTimeoutExceeded() {
				return 0, nil, os.ErrDeadlineExceeded
			}
			continue
		}
		if payloadStart > 0 || payloadEnd < n {
			payloadLen := payloadEnd - payloadStart
			copy(p[:payloadLen], p[payloadStart:payloadEnd])
			n = payloadLen
		}
		cip.TrackPacketRx(rawN)
		return n, &net.IPAddr{IP: net.IP(destination.Addr.AsSlice())}, nil
	}
}

func (c *ConnectIPNetPacketConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	if c.deadlines.writeTimeoutExceeded() {
		return 0, os.ErrDeadlineExceeded
	}
	err = c.writeOutgoingWithICMPRelay(p)
	if err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *ConnectIPNetPacketConn) Close() error { return c.Conn.Close() }

func (c *ConnectIPNetPacketConn) LocalAddr() net.Addr {
	return &net.IPAddr{IP: net.IPv4zero}
}

func (c *ConnectIPNetPacketConn) SetDeadline(t time.Time) error {
	c.deadlines.setDeadline(t)
	return nil
}

func (c *ConnectIPNetPacketConn) SetReadDeadline(t time.Time) error {
	c.deadlines.setReadDeadline(t)
	return nil
}

func (c *ConnectIPNetPacketConn) SetWriteDeadline(t time.Time) error {
	c.deadlines.setWriteDeadline(t)
	return nil
}

type connDeadlines struct {
	read  atomic.Int64
	write atomic.Int64
}

func deadlineNanos(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.UnixNano()
}

func (d *connDeadlines) setDeadline(t time.Time) {
	v := deadlineNanos(t)
	d.read.Store(v)
	d.write.Store(v)
}

func (d *connDeadlines) setReadDeadline(t time.Time) {
	d.read.Store(deadlineNanos(t))
}

func (d *connDeadlines) setWriteDeadline(t time.Time) {
	d.write.Store(deadlineNanos(t))
}

func (d *connDeadlines) readTimeoutExceeded() bool {
	v := d.read.Load()
	return v != 0 && time.Now().UnixNano() > v
}

func (d *connDeadlines) writeTimeoutExceeded() bool {
	v := d.write.Load()
	return v != 0 && time.Now().UnixNano() > v
}
