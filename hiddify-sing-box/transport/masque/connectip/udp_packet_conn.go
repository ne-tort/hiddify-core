package connectip

import (
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"
)

const (
	// UDPDirectReadMin is the minimum caller buffer size for CONNECT-IP UDP ReadFrom to
	// copy payload in-place without an intermediate staging buffer.
	UDPDirectReadMin = 2048

	// DefaultUDPWriteHardCap is the max application UDP payload per IPv4 datagram before WritePacket.
	DefaultUDPWriteHardCap = 1152

	udpBridgeEphemeralBase = 49152
	udpBridgeEphemeralSpan = 16383 // 49152..65534
)

var udpBridgeEphemeralSeq atomic.Uint32

// nextUDPBridgeLocalPort allocates a unique UDP source/bind port for multi-flow demux.
func nextUDPBridgeLocalPort() uint16 {
	n := udpBridgeEphemeralSeq.Add(1)
	return uint16(udpBridgeEphemeralBase + int(n-1)%udpBridgeEphemeralSpan)
}

var udpWriteBufPool = sync.Pool{
	New: func() any {
		b := make([]byte, 0, 2048)
		return &b
	},
}

// UDPPacketConnHost wires CONNECT-IP ingress subscribers for bridged UDP reads.
type UDPPacketConnHost interface {
	RegisterUDPIngressSubscriber(localPort uint16) *UDPIngressSubscriber
	UnregisterUDPIngressSubscriber(sub *UDPIngressSubscriber)
}

// UDPPacketConnConfig initializes a CONNECT-IP IPv4 UDP bridge net.PacketConn.
type UDPPacketConnConfig struct {
	Session           PacketSession
	Host              UDPPacketConnHost
	LocalV4           netip.Addr
	UDPPayloadHardCap int
	DatagramCeiling   int
	PMTUState         *UDPPMTUState
}

// UDPPacketConn bridges net.UDPConn semantics over CONNECT-IP WritePacket/ReadPacket (IPv4 only).
type UDPPacketConn struct {
	session          PacketSession
	host             UDPPacketConnHost
	ingressSub       *UDPIngressSubscriber
	ingressUnregOnce sync.Once
	localV4          netip.Addr
	localBind        *net.UDPAddr
	pmtuState        *UDPPMTUState
	deadlines        PacketDeadlines
	readMu           sync.Mutex
	readBuffer       []byte
	readScratchAddr  net.UDPAddr
	icmpNotify       chan error
	icmpWake         chan struct{}
	closed           atomic.Bool
}

// NewUDPPacketConn builds a CONNECT-IP UDP bridge packet conn from resolved session parameters.
func NewUDPPacketConn(cfg UDPPacketConnConfig) net.PacketConn {
	localV4 := cfg.LocalV4
	if !localV4.Is4() {
		localV4 = netip.MustParseAddr("198.18.0.1")
	}
	maxDatagram := 1200
	if cfg.DatagramCeiling > 0 {
		maxDatagram = cfg.DatagramCeiling
	}
	udpHardCap := DefaultUDPWriteHardCap
	if cfg.UDPPayloadHardCap > 0 {
		udpHardCap = cfg.UDPPayloadHardCap
	}
	defaultPayload := udpHardCap
	if defaultPayload > maxDatagram-28 {
		defaultPayload = maxDatagram - 28
	}
	if defaultPayload < 512 {
		defaultPayload = 512
	}
	pmtuState := cfg.PMTUState
	if pmtuState == nil {
		pmtuState = NewUDPPMTUState(defaultPayload, 512, defaultPayload)
	}
	maxUDPPayload := maxDatagram - 28
	if maxUDPPayload <= 0 {
		maxUDPPayload = 512
	}
	if maxUDPPayload > udpHardCap {
		maxUDPPayload = udpHardCap
	}
	pmtuState.Mu.Lock()
	pmtuState.MaxPayload.Store(int64(maxUDPPayload))
	cur := pmtuState.CurrentPayload.Load()
	if cur <= 0 || cur > int64(maxUDPPayload) {
		cur = int64(maxUDPPayload)
		pmtuState.CurrentPayload.Store(cur)
	}
	if minP := pmtuState.MinPayload.Load(); minP <= 0 || minP > cur {
		pmtuState.MinPayload.Store(512)
	}
	currentPayload := int(cur)
	pmtuState.Mu.Unlock()
	obsEffectiveUDPPayload(currentPayload, "session_init")
	l4 := localV4.As4()
	localIP := net.IPv4(l4[0], l4[1], l4[2], l4[3])
	localPort := nextUDPBridgeLocalPort()
	pc := &UDPPacketConn{
		session:         cfg.Session,
		host:            cfg.Host,
		localV4:         localV4,
		localBind:       &net.UDPAddr{IP: localIP, Port: int(localPort)},
		pmtuState:       pmtuState,
		readScratchAddr: net.UDPAddr{IP: make(net.IP, 0, 16)},
		icmpNotify:      make(chan error, 4),
		icmpWake:        make(chan struct{}, 1),
	}
	if cfg.Host != nil {
		pc.ingressSub = cfg.Host.RegisterUDPIngressSubscriber(localPort)
	}
	return pc
}

// HasReadBuffer reports whether a staging read buffer was allocated (tests).
func (c *UDPPacketConn) HasReadBuffer() bool {
	return c.readBuffer != nil
}

func (c *UDPPacketConn) Close() error {
	c.closed.Store(true)
	if c.host != nil && c.ingressSub != nil {
		c.ingressUnregOnce.Do(func() {
			c.host.UnregisterUDPIngressSubscriber(c.ingressSub)
		})
	}
	return nil
}

func (c *UDPPacketConn) LocalAddr() net.Addr {
	return c.localBind
}

func (c *UDPPacketConn) SetDeadline(t time.Time) error {
	c.deadlines.SetDeadline(t)
	return nil
}

func (c *UDPPacketConn) SetReadDeadline(t time.Time) error {
	c.deadlines.SetReadDeadline(t)
	return nil
}

func (c *UDPPacketConn) SetWriteDeadline(t time.Time) error {
	c.deadlines.SetWriteDeadline(t)
	return nil
}
