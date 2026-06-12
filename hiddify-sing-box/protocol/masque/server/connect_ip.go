package server

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"time"

	connectip "github.com/quic-go/connect-ip-go"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	fwd "github.com/sagernet/sing-box/transport/masque/forwarder"
	TM "github.com/sagernet/sing-box/transport/masque"
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

// ConnectIPRequestErrorHTTPStatus maps connect-ip-go parse errors to HTTP status codes.
func ConnectIPRequestErrorHTTPStatus(err error) int {
	var perr *connectip.RequestParseError
	if errors.As(err, &perr) {
		return perr.HTTPStatus
	}
	return 400
}

// ConnectIPRequestErrorClass maps HTTP status to transport error class.
func ConnectIPRequestErrorClass(status int) TM.ErrorClass {
	switch status {
	case 400, 501:
		return TM.ErrorClassCapability
	default:
		return TM.ErrorClassUnknown
	}
}

// ConnectIPRouteAdvertiseErrorClass maps route advertise failures to error class.
func ConnectIPRouteAdvertiseErrorClass(err error) TM.ErrorClass {
	if err == nil {
		return TM.ErrorClassUnknown
	}
	if errors.Is(err, net.ErrClosed) {
		return TM.ErrorClassLifecycle
	}
	if errors.Is(err, connectip.ErrInvalidRouteAdvertisement) {
		return TM.ErrorClassCapability
	}
	return TM.ErrorClassTransport
}

// DataplaneContext returns a context for CONNECT-IP packet-plane work that does not
// propagate cancellation from the inbound HTTP request. sing-box Router forwards the same ctx into
// matchRule and outbound packet handlers; req.Context may cancel independently of relay lifetime.
func DataplaneContext(reqCtx context.Context) context.Context {
	return context.WithoutCancel(reqCtx)
}

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

// RouteConnectIPBlocked keeps the HTTP handler alive until the CONNECT-IP packet-plane
// relay ends. On HTTP/3 the stream is hijacked via http3.HTTPStreamer inside connect-ip Proxy,
// so ending the handler does not close the QUIC stream. On HTTP/2 Extended CONNECT there is no
// hijack; if the handler returned immediately, net/http would finalize the response and tear down
// the CONNECT stream while RoutePacketConnectionEx goroutines were still running.
func RouteConnectIPBlocked(router adapter.Router, reqCtx context.Context, packetConn *ConnectIPNetPacketConn, metadata adapter.InboundContext, logger log.ContextLogger, opts option.MasqueEndpointOptions, onwardDialer net.Dialer) {
	done := make(chan struct{})
	var once sync.Once
	notify := func() { once.Do(func() { close(done) }) }
	onClose := func(err error) {
		if err != nil && !errors.Is(err, context.Canceled) && logger != nil {
			logger.DebugContext(reqCtx, fmt.Sprintf("masque connect-ip route closed err=%v", err))
		}
		_ = packetConn.Close()
		notify()
	}
	// TCP inside CONNECT-IP is raw IPv4/TCP on connectip.Conn. RoutePacketConnectionEx models UDP
	// extracted payloads (metadata.Network=UDP) and drops TCP SYNs in ConnectIPNetPacketConn.ReadPacket,
	// which tears down the QUIC/H3 session (bench connect-ip iperf FAIL, ingress_read_closed).
	// Terminate IPv4/TCP in the S2 packet-plane forwarder on the live connectip.Conn instead.
	_ = router
	_ = metadata
	fwdCtx := DataplaneContext(reqCtx)
	fwdOpts := fwd.ConnectIPTCPForwarderOptions{
		AllowPrivateTargets: opts.AllowPrivateTargets,
		AllowedTargetPorts:  opts.AllowedTargetPorts,
		BlockedTargetPorts:  opts.BlockedTargetPorts,
		Dialer:              onwardDialer,
	}
	go func() {
		err := fwd.RunConnectIPTCPPacketPlaneForwarder(fwdCtx, packetConn.Conn, fwdOpts)
		onClose(err)
	}()
	<-done
}

func (c *ConnectIPNetPacketConn) ReadPacket(buffer *buf.Buffer) (destination M.Socksaddr, err error) {
	for {
		n, err := c.Conn.ReadPacket(buffer.FreeBytes())
		if err != nil {
			TM.ObserveConnectIPServerReadError(err)
			return M.Socksaddr{}, err
		}
		buffer.Truncate(n)
		destination, payloadStart, payloadEnd, parseErr := ParseIPDestinationAndPayload(buffer.Bytes())
		if parseErr != nil {
			connectIPServerParseDropTotal.Add(1)
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
		TM.ObserveConnectIPServerReadSuccess(n)
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
		TM.ObserveConnectIPServerWriteIteration(len(payload), len(icmp), err)
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
	for {
		n, err = c.Conn.ReadPacket(p)
		if err != nil {
			TM.ObserveConnectIPServerReadError(err)
			return 0, nil, err
		}
		rawN := n
		destination, payloadStart, payloadEnd, parseErr := ParseIPDestinationAndPayload(p[:n])
		if parseErr != nil {
			connectIPServerParseDropTotal.Add(1)
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
		TM.ObserveConnectIPServerReadSuccess(rawN)
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

// ParseIPDestinationAndPayload extracts destination and UDP payload bounds from a raw IP packet.
func ParseIPDestinationAndPayload(packet []byte) (M.Socksaddr, int, int, error) {
	if len(packet) < 1 {
		return M.Socksaddr{}, 0, 0, E.New("invalid empty ip packet")
	}
	switch packet[0] >> 4 {
	case 4:
		if len(packet) < 20 {
			return M.Socksaddr{}, 0, 0, E.New("invalid ipv4 packet")
		}
		ihl := int(packet[0]&0x0f) * 4
		if ihl < 20 || len(packet) < ihl {
			return M.Socksaddr{}, 0, 0, E.New("invalid ipv4 header length")
		}
		destination := M.Socksaddr{Addr: netip.AddrFrom4([4]byte(packet[16:20]))}
		protocol := packet[9]
		if (packet[9] == 6 || packet[9] == 17) && len(packet) >= ihl+4 {
			destination.Port = uint16(packet[ihl+2])<<8 | uint16(packet[ihl+3])
		}
		payloadStart, payloadEnd := 0, len(packet)
		if protocol == 17 && len(packet) >= ihl+8 {
			totalLen := int(uint16(packet[2])<<8 | uint16(packet[3]))
			if totalLen <= 0 || totalLen > len(packet) {
				totalLen = len(packet)
			}
			udpLen := int(uint16(packet[ihl+4])<<8 | uint16(packet[ihl+5]))
			payloadStart = ihl + 8
			payloadEnd = totalLen
			if udpLen >= 8 {
				payloadEnd = intMin(payloadEnd, ihl+udpLen)
			}
			if payloadStart > payloadEnd || payloadEnd > len(packet) {
				return M.Socksaddr{}, 0, 0, E.New("invalid ipv4 udp payload")
			}
		}
		return destination, payloadStart, payloadEnd, nil
	case 6:
		if len(packet) < 40 {
			return M.Socksaddr{}, 0, 0, E.New("invalid ipv6 packet")
		}
		destination := M.Socksaddr{Addr: netip.AddrFrom16([16]byte(packet[24:40]))}
		nextHeader, transportOffset, err := ipv6TransportHeaderOffset(packet)
		if err != nil {
			return M.Socksaddr{}, 0, 0, err
		}
		if (nextHeader == 6 || nextHeader == 17) && len(packet) >= transportOffset+4 {
			destination.Port = uint16(packet[transportOffset+2])<<8 | uint16(packet[transportOffset+3])
		}
		payloadStart, payloadEnd := 0, len(packet)
		if nextHeader == 17 && len(packet) >= transportOffset+8 {
			payloadStart = transportOffset + 8
			totalLen := len(packet)
			ipPayloadLen := int(uint16(packet[4])<<8 | uint16(packet[5]))
			if ipPayloadLen > 0 {
				totalLen = intMin(totalLen, 40+ipPayloadLen)
			}
			payloadEnd = totalLen
			udpLen := int(uint16(packet[transportOffset+4])<<8 | uint16(packet[transportOffset+5]))
			if udpLen >= 8 {
				payloadEnd = intMin(payloadEnd, transportOffset+udpLen)
			}
			if payloadStart > payloadEnd || payloadEnd > len(packet) {
				return M.Socksaddr{}, 0, 0, E.New("invalid ipv6 udp payload")
			}
		}
		return destination, payloadStart, payloadEnd, nil
	default:
		return M.Socksaddr{}, 0, 0, E.New("unsupported ip packet version")
	}
}

func ipv6TransportHeaderOffset(packet []byte) (uint8, int, error) {
	nextHeader := packet[6]
	offset := 40
	for {
		switch nextHeader {
		case 0, 43, 60, 135, 139, 140, 253, 254:
			if len(packet) < offset+2 {
				return 0, 0, E.New("invalid ipv6 extension header")
			}
			headerLen := int(packet[offset+1]+1) * 8
			if headerLen <= 0 || len(packet) < offset+headerLen {
				return 0, 0, E.New("invalid ipv6 extension header length")
			}
			nextHeader = packet[offset]
			offset += headerLen
		case 44:
			if len(packet) < offset+8 {
				return 0, 0, E.New("invalid ipv6 fragment header")
			}
			nextHeader = packet[offset]
			offset += 8
		default:
			return nextHeader, offset, nil
		}
	}
}

func intMin(a, b int) int {
	if a < b {
		return a
	}
	return b
}
