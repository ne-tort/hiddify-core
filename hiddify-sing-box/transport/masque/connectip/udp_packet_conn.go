package connectip

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

)

const (
	// UDPDirectReadMin is the minimum caller buffer size for CONNECT-IP UDP ReadFrom to
	// copy payload in-place without an intermediate staging buffer.
	UDPDirectReadMin = 2048

	// DefaultUDPWriteHardCap is the max application UDP payload per IPv4 datagram before WritePacket.
	DefaultUDPWriteHardCap = 1152

	defaultUDPLocalBindPort = 53000
	defaultUDPSrcPort       = 53000
)

var udpWriteBufPool = sync.Pool{
	New: func() any {
		b := make([]byte, 0, 2048)
		return &b
	},
}

// UDPPacketConnHost wires CONNECT-IP ingress subscribers for bridged UDP reads.
type UDPPacketConnHost interface {
	RegisterUDPIngressSubscriber() *UDPIngressSubscriber
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
	pc := &UDPPacketConn{
		session:         cfg.Session,
		host:            cfg.Host,
		localV4:         localV4,
		localBind:       &net.UDPAddr{IP: localIP, Port: defaultUDPLocalBindPort},
		pmtuState:       pmtuState,
		readScratchAddr: net.UDPAddr{IP: make(net.IP, 0, 16)},
		icmpNotify:      make(chan error, 4),
		icmpWake:        make(chan struct{}, 1),
	}
	if cfg.Host != nil {
		pc.ingressSub = cfg.Host.RegisterUDPIngressSubscriber()
	}
	return pc
}

// HasReadBuffer reports whether a staging read buffer was allocated (tests).
func (c *UDPPacketConn) HasReadBuffer() bool {
	return c.readBuffer != nil
}

func (c *UDPPacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	if c.closed.Load() {
		return 0, nil, net.ErrClosed
	}
	if c.deadlines.ReadTimeoutExceeded() {
		return 0, nil, os.ErrDeadlineExceeded
	}

	ctx := context.Background()
	if v := c.deadlines.readDeadline(); v != 0 {
		if time.Now().UnixNano() > v {
			return 0, nil, os.ErrDeadlineExceeded
		}
		deadline := time.Unix(0, v)
		var cancel context.CancelFunc
		ctx, cancel = context.WithDeadline(context.Background(), deadline)
		defer cancel()
	}

	c.readMu.Lock()
	defer c.readMu.Unlock()

	if err := c.takeICMPPortUnreachable(); err != nil {
		return 0, nil, err
	}

	if c.ingressSub != nil {
		for {
			if c.closed.Load() {
				return 0, nil, net.ErrClosed
			}
			if c.deadlines.ReadTimeoutExceeded() {
				return 0, nil, os.ErrDeadlineExceeded
			}
			if err := c.takeICMPPortUnreachable(); err != nil {
				return 0, nil, err
			}
			select {
			case <-ctx.Done():
				return 0, nil, os.ErrDeadlineExceeded
			case err := <-c.icmpNotify:
				return 0, nil, err
			case raw, ok := <-c.ingressSub.Ch:
				if !ok {
					return 0, nil, net.ErrClosed
				}
				if peer, port, icmpOK := ParseICMPPortUnreachablePeer(raw); icmpOK {
					c.readScratchAddr.IP = append(c.readScratchAddr.IP[:0], peer.AsSlice()...)
					c.readScratchAddr.Port = int(port)
					return 0, &c.readScratchAddr, NewICMPPortUnreachableError(&c.readScratchAddr)
				}
				obsEngineIngress()
				payloadOff, payloadLen, src, srcPort, parseErr := ParseIPv4UDPPacketOffsets(raw)
				if parseErr != nil {
					obsEngineDrop("read_parse")
					continue
				}
				obsEngineClassified()
				src4 := src.As4()
				c.readScratchAddr.IP = append(c.readScratchAddr.IP[:0], src4[:]...)
				c.readScratchAddr.Port = int(srcPort)
				if len(p) >= UDPDirectReadMin {
					if payloadLen > len(p) {
						return 0, nil, fmt.Errorf("connect-ip udp bridge: UDP payload exceeds read buffer (%d > %d)", payloadLen, len(p))
					}
					if payloadLen > 0 {
						if payloadOff+payloadLen > len(raw) {
							return 0, nil, fmt.Errorf("connect-ip udp bridge: UDP payload out of read bounds (%d+%d>%d)", payloadOff, payloadLen, len(raw))
						}
						copy(p[:payloadLen], raw[payloadOff:payloadOff+payloadLen])
					}
					return payloadLen, &c.readScratchAddr, nil
				}
				return copy(p, raw[payloadOff:payloadOff+payloadLen]), &c.readScratchAddr, nil
			}
		}
	}

	var sctx PacketSessionWithContext
	sctx, _ = c.session.(PacketSessionWithContext)
	for {
		if err := c.takeICMPPortUnreachable(); err != nil {
			return 0, nil, err
		}
		readCtx := ctx
		if sctx != nil {
			var cancelRead context.CancelFunc
			readCtx, cancelRead = context.WithCancel(ctx)
			defer cancelRead()
			go func() {
				select {
				case <-c.icmpWake:
					cancelRead()
				case <-readCtx.Done():
				}
			}()
		}
		var raw []byte
		if len(p) >= UDPDirectReadMin {
			if sctx != nil {
				n, err = sctx.ReadPacketWithContext(readCtx, p)
			} else {
				n, err = c.session.ReadPacket(p)
			}
			raw = p[:n]
		} else {
			rb := c.readBuffer
			if rb == nil {
				rb = make([]byte, 64*1024)
				c.readBuffer = rb
			}
			if sctx != nil {
				n, err = sctx.ReadPacketWithContext(readCtx, rb)
			} else {
				n, err = c.session.ReadPacket(rb)
			}
			raw = rb[:n]
		}
		if err != nil {
			if icmpErr := c.takeICMPPortUnreachable(); icmpErr != nil {
				return 0, nil, icmpErr
			}
			if errors.Is(err, context.DeadlineExceeded) {
				return 0, nil, os.ErrDeadlineExceeded
			}
			if errors.Is(err, context.Canceled) {
				if c.deadlines.ReadTimeoutExceeded() {
					return 0, nil, os.ErrDeadlineExceeded
				}
				continue
			}
			return 0, nil, err
		}
		if peer, port, icmpOK := ParseICMPPortUnreachablePeer(raw); icmpOK {
			c.readScratchAddr.IP = append(c.readScratchAddr.IP[:0], peer.AsSlice()...)
			c.readScratchAddr.Port = int(port)
			return 0, &c.readScratchAddr, NewICMPPortUnreachableError(&c.readScratchAddr)
		}
		obsEngineIngress()
		payloadOff, payloadLen, src, srcPort, parseErr := ParseIPv4UDPPacketOffsets(raw)
		if parseErr != nil {
			obsEngineDrop("read_parse")
			if c.deadlines.ReadTimeoutExceeded() {
				return 0, nil, os.ErrDeadlineExceeded
			}
			continue
		}
		obsEngineClassified()
		src4 := src.As4()
		c.readScratchAddr.IP = append(c.readScratchAddr.IP[:0], src4[:]...)
		c.readScratchAddr.Port = int(srcPort)
		if len(p) >= UDPDirectReadMin {
			if payloadLen > len(p) {
				return 0, nil, fmt.Errorf("connect-ip udp bridge: UDP payload exceeds read buffer (%d > %d)", payloadLen, len(p))
			}
			if payloadLen > 0 {
				if payloadOff+payloadLen > len(raw) {
					return 0, nil, fmt.Errorf("connect-ip udp bridge: UDP payload out of read bounds (%d+%d>%d)", payloadOff, payloadLen, len(raw))
				}
				copy(p[:payloadLen], raw[payloadOff:payloadOff+payloadLen])
			}
			return payloadLen, &c.readScratchAddr, nil
		}
		return copy(p, raw[payloadOff:payloadOff+payloadLen]), &c.readScratchAddr, nil
	}
}

func (c *UDPPacketConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	if c.closed.Load() {
		return 0, net.ErrClosed
	}
	if c.deadlines.WriteTimeoutExceeded() {
		return 0, os.ErrDeadlineExceeded
	}
	udpAddr, ok := addr.(*net.UDPAddr)
	if !ok || udpAddr == nil || udpAddr.Port <= 0 {
		return 0, errors.New("connect-ip udp bridge requires UDP destination")
	}
	ip4 := udpAddr.IP.To4()
	if ip4 == nil {
		return 0, errors.New("connect-ip udp bridge requires valid IPv4 destination")
	}
	src4 := c.localV4.As4()
	dst4 := [4]byte{ip4[0], ip4[1], ip4[2], ip4[3]}
	dstPort := uint16(udpAddr.Port)
	headerTemplate := NewIPv4UDPHeaderTemplate(src4, defaultUDPSrcPort, dst4, dstPort)

	bufPtr := udpWriteBufPool.Get().(*[]byte)
	defer func() {
		b := *bufPtr
		b = b[:0]
		*bufPtr = b
		udpWriteBufPool.Put(bufPtr)
	}()
	writeBuf := *bufPtr

	obsBridgeWriteEnter()
	obsBridgeUDPTXAttempt()
	maxPayload := c.currentPayloadCeiling()
	offset := 0
	first := true
	for first || offset < len(p) {
		if c.deadlines.WriteTimeoutExceeded() {
			if offset > 0 {
				return offset, os.ErrDeadlineExceeded
			}
			return 0, os.ErrDeadlineExceeded
		}
		first = false
		obsBridgeWriteChunk()
		end := offset + maxPayload
		if end > len(p) {
			end = len(p)
		}
		const localMTURetryMax = 3
		localRetries := 0
		for {
			if c.deadlines.WriteTimeoutExceeded() {
				if offset > 0 {
					return offset, os.ErrDeadlineExceeded
				}
				return 0, os.ErrDeadlineExceeded
			}
			packet, buildErr := BuildIPv4UDPPacketInplaceHeaderV4(writeBuf, headerTemplate, p[offset:end])
			if buildErr != nil {
				obsBridgeWriteErr("build_packet")
				return 0, buildErr
			}
			obsBridgeBuild()
			writeBuf = packet[:0]
			*bufPtr = writeBuf
			icmp, writeErr := c.session.WritePacket(packet)
			err = writeErr
			if err == nil {
				obsBridgeWriteOK()
				obsEngineClassified()
				if len(icmp) > 0 {
					obsEngineICMPFeedback()
					if peer, port, icmpOK := ParseICMPPortUnreachablePeer(icmp); icmpOK {
						c.notifyICMPPortUnreachable(peer, port)
					} else if ipMTU, isV6, ok := ParseICMPPTBHopMTU(icmp); ok {
						maxPayload = c.applyPTBToUDPPayload(ipMTU, isV6)
					} else {
						maxPayload = c.decreasePayloadCeiling("ptb_feedback")
					}
				} else {
					maxPayload = c.maybeRecoverPayloadCeiling()
				}
				break
			}
			if obsClassifyWriteError(err) == "mtu" && localRetries < localMTURetryMax {
				nextPayload := c.decreasePayloadCeiling("local_mtu_error")
				if nextPayload > 0 {
					nextEnd := offset + nextPayload
					if nextEnd > len(p) {
						nextEnd = len(p)
					}
					if nextEnd > offset && nextEnd < end {
						end = nextEnd
						localRetries++
						continue
					}
				}
			}
			obsBridgeWriteErr("session_write_packet")
			return 0, err
		}
		offset = end
	}
	return len(p), nil
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

func (c *UDPPacketConn) notifyICMPPortUnreachable(peer netip.Addr, port uint16) {
	if !peer.IsValid() || port == 0 {
		return
	}
	err := NewICMPPortUnreachableError(&net.UDPAddr{IP: peer.AsSlice(), Port: int(port)})
	select {
	case c.icmpNotify <- err:
	default:
		select {
		case <-c.icmpNotify:
		default:
		}
		c.icmpNotify <- err
	}
	select {
	case c.icmpWake <- struct{}{}:
	default:
	}
}

func (c *UDPPacketConn) takeICMPPortUnreachable() error {
	select {
	case err := <-c.icmpNotify:
		return err
	default:
		return nil
	}
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

func (c *UDPPacketConn) currentPayloadCeiling() int {
	if c.pmtuState == nil {
		return 1172
	}
	if v := c.pmtuState.CurrentPayload.Load(); v > 0 {
		return int(v)
	}
	c.pmtuState.Mu.Lock()
	if v := c.pmtuState.CurrentPayload.Load(); v > 0 {
		c.pmtuState.Mu.Unlock()
		return int(v)
	}
	c.pmtuState.CurrentPayload.Store(1172)
	c.pmtuState.Mu.Unlock()
	return 1172
}

func (c *UDPPacketConn) applyPTBToUDPPayload(ipPathMTU int, isIPv6 bool) int {
	if c.pmtuState == nil {
		return 1172
	}
	overhead := 28
	if isIPv6 {
		overhead = 48
	}
	udpMax := ipPathMTU - overhead
	if udpMax < 512 {
		udpMax = 512
	}
	c.pmtuState.Mu.Lock()
	cur := c.pmtuState.CurrentPayload.Load()
	if cur <= 0 {
		cur = 1172
		c.pmtuState.CurrentPayload.Store(cur)
	}
	if maxP := c.pmtuState.MaxPayload.Load(); maxP > 0 && int64(udpMax) > maxP {
		udpMax = int(maxP)
	}
	if int64(udpMax) < cur {
		c.pmtuState.CurrentPayload.Store(int64(udpMax))
		c.pmtuState.SuccessSinceDecrease.Store(0)
		cur = int64(udpMax)
	}
	c.pmtuState.Mu.Unlock()
	current := int(cur)
	obsEffectiveUDPPayload(current, "ptb_mtu_hint")
	return current
}

func (c *UDPPacketConn) decreasePayloadCeiling(reason string) int {
	if c.pmtuState == nil {
		return 1172
	}
	const pmtuMinus64DebounceMs = 80
	c.pmtuState.Mu.Lock()
	cur := c.pmtuState.CurrentPayload.Load()
	if cur <= 0 {
		cur = 1172
		c.pmtuState.CurrentPayload.Store(cur)
	}
	if reason == "ptb_feedback" {
		now := time.Now().UnixMilli()
		if last := c.pmtuState.LastMinus64UnixMilli.Load(); last != 0 && now-last < pmtuMinus64DebounceMs {
			c.pmtuState.Mu.Unlock()
			return int(cur)
		}
		c.pmtuState.LastMinus64UnixMilli.Store(now)
	}
	minP := c.pmtuState.MinPayload.Load()
	next := cur - 64
	if next < minP {
		next = minP
	}
	if next < cur {
		c.pmtuState.CurrentPayload.Store(next)
		c.pmtuState.SuccessSinceDecrease.Store(0)
		cur = next
	}
	c.pmtuState.Mu.Unlock()
	current := int(cur)
	obsEffectiveUDPPayload(current, reason)
	return current
}

func (c *UDPPacketConn) maybeRecoverPayloadCeiling() int {
	if c.pmtuState == nil {
		return 1172
	}
	const recoverySuccessWindow = 256
	cur := c.pmtuState.CurrentPayload.Load()
	maxP := c.pmtuState.MaxPayload.Load()
	if cur <= 0 {
		c.pmtuState.Mu.Lock()
		cur = c.pmtuState.CurrentPayload.Load()
		if cur <= 0 {
			cur = 1172
			c.pmtuState.CurrentPayload.Store(cur)
		}
		maxP = c.pmtuState.MaxPayload.Load()
		c.pmtuState.Mu.Unlock()
	}
	n := c.pmtuState.SuccessSinceDecrease.Add(1)
	if maxP > 0 && cur >= maxP {
		return int(cur)
	}
	if n < recoverySuccessWindow {
		return int(cur)
	}
	c.pmtuState.Mu.Lock()
	cur = c.pmtuState.CurrentPayload.Load()
	maxP = c.pmtuState.MaxPayload.Load()
	if maxP > 0 && cur >= maxP {
		c.pmtuState.Mu.Unlock()
		return int(cur)
	}
	if c.pmtuState.SuccessSinceDecrease.Load() < recoverySuccessWindow {
		c.pmtuState.Mu.Unlock()
		return int(cur)
	}
	next := cur + 16
	if maxP > 0 && next > maxP {
		next = maxP
	}
	c.pmtuState.CurrentPayload.Store(next)
	c.pmtuState.SuccessSinceDecrease.Store(0)
	c.pmtuState.Mu.Unlock()
	obsEffectiveUDPPayload(int(next), "recovery_increase")
	return int(next)
}
