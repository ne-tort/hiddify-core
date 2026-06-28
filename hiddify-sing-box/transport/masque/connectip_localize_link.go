package masque

// Windowed IPPacketSession link for CONNECT-IP localize benches (W-IP-5 IP-TEST-02; W-IP-6 .go move).

import (
	"io"
	"net"
	"sync"
	"time"
)

type packetLink interface {
	endpoints() (IPPacketSession, IPPacketSession)
}

type instantPacketLink struct{}

func (instantPacketLink) endpoints() (IPPacketSession, IPPacketSession) {
	a, b := newPacketPipePair()
	return a, b
}

type prodInstantPacketLink struct{}

func (prodInstantPacketLink) endpoints() (IPPacketSession, IPPacketSession) {
	return clientPacketSessionLink{inner: instantPacketLink{}}.endpoints()
}

// windowedPacketLink limits client→server bytes in flight and adds RTT per packet
// (bench-shaped ~64 KiB / RTT ≈ 13–15 Mbit/s at 35 ms).
type windowedPacketLink struct {
	rtt         time.Duration
	windowBytes int
}

func benchWindowedPacketLink() windowedPacketLink {
	return windowedPacketLink{
		rtt:         localizeBenchRTT,
		windowBytes: localizeBenchWindowBytes,
	}
}

func (w windowedPacketLink) endpoints() (IPPacketSession, IPPacketSession) {
	return newWindowedPacketPair(w.rtt, w.windowBytes)
}

func newWindowedPacketPair(rtt time.Duration, windowBytes int) (IPPacketSession, IPPacketSession) {
	if windowBytes <= 0 {
		windowBytes = localizeBenchWindowBytes
	}
	if rtt <= 0 {
		rtt = localizeBenchRTT
	}
	bridge := &windowedPacketBridge{
		rtt:         rtt,
		windowBytes: windowBytes,
		clientRx:    make(chan []byte, 256),
		serverRx:    make(chan []byte, 256),
	}
	bridge.cond = sync.NewCond(&bridge.mu)
	client := &bridgePacketSession{bridge: bridge, role: bridgeRoleClient, done: make(chan struct{})}
	server := &bridgePacketSession{bridge: bridge, role: bridgeRoleServer, done: make(chan struct{})}
	return client, server
}

// bridgePacketSession implements IPPacketSession with RTT + in-flight window.
type bridgePacketSession struct {
	bridge *windowedPacketBridge
	role   bridgeRole
	once   sync.Once
	done   chan struct{}
}

func (s *bridgePacketSession) ReadPacket(buffer []byte) (int, error) {
	rx := s.bridge.clientRx
	if s.role == bridgeRoleServer {
		rx = s.bridge.serverRx
	}
	select {
	case <-s.done:
		return 0, net.ErrClosed
	case pkt, ok := <-rx:
		if !ok {
			return 0, io.EOF
		}
		if len(pkt) > len(buffer) {
			return 0, io.ErrShortBuffer
		}
		return copy(buffer, pkt), nil
	}
}

func (s *bridgePacketSession) WritePacket(buffer []byte) ([]byte, error) {
	if err := s.bridge.write(s.role, buffer); err != nil {
		return nil, err
	}
	return nil, nil
}

func (s *bridgePacketSession) Close() error {
	s.once.Do(func() {
		close(s.done)
		s.bridge.closeBridge()
	})
	return nil
}

type bridgeRole int

const (
	bridgeRoleClient bridgeRole = iota
	bridgeRoleServer
)

type windowedPacketBridge struct {
	mu                sync.Mutex
	cond              *sync.Cond
	rtt               time.Duration
	windowBytes       int
	inflightC2S       int
	inflightS2C       int
	pendingRelease    int
	pendingReleaseS2C int
	releaseTimer      *time.Timer
	clientRx          chan []byte
	serverRx          chan []byte
	closed            bool
}

func (b *windowedPacketBridge) write(role bridgeRole, pkt []byte) error {
	tcpPayload := -1
	tcpAckOnly := false
	tcpOK := false
	if payloadLen, ackOnly, ok := connectIPLocalizeTCPMeta(pkt); ok {
		tcpPayload = payloadLen
		tcpAckOnly = ackOnly
		tcpOK = true
	}
	isC2SData := role == bridgeRoleClient && tcpOK && tcpPayload > 0
	isS2CData := role == bridgeRoleServer && tcpOK && tcpPayload > 0
	isAck := tcpOK && tcpAckOnly

	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		return net.ErrClosed
	}
	if isC2SData {
		charge := tcpPayload
		for b.inflightC2S+charge > b.windowBytes && !b.closed {
			b.cond.Wait()
		}
		if b.closed {
			b.mu.Unlock()
			return net.ErrClosed
		}
		b.inflightC2S += charge
	}
	if isS2CData {
		charge := tcpPayload
		for b.inflightS2C+charge > b.windowBytes && !b.closed {
			b.cond.Wait()
		}
		if b.closed {
			b.mu.Unlock()
			return net.ErrClosed
		}
		b.inflightS2C += charge
	}
	b.mu.Unlock()

	dst := b.serverRx
	if role == bridgeRoleServer {
		dst = b.clientRx
	}
	p := append([]byte(nil), pkt...)
	if isAck && role == bridgeRoleServer && b.rtt > 0 {
		time.Sleep(b.rtt)
	}

	deliver := func() error {
		timer := time.NewTimer(250 * time.Millisecond)
		defer timer.Stop()
		select {
		case dst <- p:
			if isAck {
				credit := connectIPLocalizeAckCredit(pkt)
				if role == bridgeRoleServer {
					b.releaseC2S(credit)
				} else {
					b.scheduleReleaseS2C(credit)
				}
			}
			return nil
		case <-timer.C:
			if isAck {
				credit := connectIPLocalizeAckCredit(pkt)
				if role == bridgeRoleServer {
					b.releaseC2S(credit)
				} else {
					b.scheduleReleaseS2C(credit)
				}
			}
			return io.ErrShortBuffer
		}
	}
	if err := deliver(); err != nil {
		if isC2SData {
			b.rollbackInflightC2S(tcpPayload)
		}
		if isS2CData {
			b.rollbackInflightS2C(tcpPayload)
		}
		return err
	}
	return nil
}

func (b *windowedPacketBridge) rollbackInflightC2S(charge int) {
	if charge <= 0 {
		return
	}
	b.mu.Lock()
	b.inflightC2S -= charge
	if b.inflightC2S < 0 {
		b.inflightC2S = 0
	}
	b.cond.Broadcast()
	b.mu.Unlock()
}

func (b *windowedPacketBridge) rollbackInflightS2C(charge int) {
	if charge <= 0 {
		return
	}
	b.mu.Lock()
	b.inflightS2C -= charge
	if b.inflightS2C < 0 {
		b.inflightS2C = 0
	}
	b.cond.Broadcast()
	b.mu.Unlock()
}

func connectIPLocalizeIsIPv4TCP(pkt []byte) bool {
	return len(pkt) >= 20 && pkt[0]>>4 == 4 && pkt[9] == 6
}

func connectIPLocalizeTCPMeta(pkt []byte) (payloadLen int, ackOnly bool, ok bool) {
	if !connectIPLocalizeIsIPv4TCP(pkt) {
		return -1, false, false
	}
	ihl := int(pkt[0]&0x0f) * 4
	if ihl+14 > len(pkt) {
		return -1, false, false
	}
	doff := int(pkt[ihl+12]>>4) * 4
	if doff < 20 || ihl+doff > len(pkt) {
		return -1, false, false
	}
	payloadLen = len(pkt) - ihl - doff
	ackOnly = payloadLen == 0 && pkt[ihl+13]&0x10 != 0
	return payloadLen, ackOnly, true
}

func connectIPLocalizeTCPPayloadLen(pkt []byte) int {
	payloadLen, _, ok := connectIPLocalizeTCPMeta(pkt)
	if !ok {
		return -1
	}
	return payloadLen
}

// connectIPLocalizeAckCredit estimates TCP window credit returned by one server→client segment.
func connectIPLocalizeAckCredit(pkt []byte) int {
	const defaultMSS = 1300
	if len(pkt) < 20 || pkt[0]>>4 != 4 || pkt[9] != 6 {
		return defaultMSS
	}
	ihl := int(pkt[0]&0x0f) * 4
	if ihl+12 > len(pkt) {
		return defaultMSS
	}
	doff := int(pkt[ihl+12]>>4) * 4
	if doff < 20 || ihl+doff > len(pkt) {
		return defaultMSS
	}
	payload := len(pkt) - ihl - doff
	if payload > 0 {
		return payload
	}
	return defaultMSS
}

func (b *windowedPacketBridge) scheduleRelease(credit int) {
	if credit <= 0 {
		return
	}
	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		return
	}
	b.pendingRelease += credit
	if b.releaseTimer == nil && b.rtt > 0 {
		b.releaseTimer = time.AfterFunc(b.rtt, b.flushRelease)
	} else if b.releaseTimer == nil {
		b.flushReleaseLocked()
	}
	b.mu.Unlock()
}

func (b *windowedPacketBridge) flushRelease() {
	b.mu.Lock()
	b.flushReleaseLocked()
	b.mu.Unlock()
}

func (b *windowedPacketBridge) scheduleReleaseS2C(credit int) {
	if credit <= 0 {
		return
	}
	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		return
	}
	b.pendingReleaseS2C += credit
	if b.releaseTimer == nil && b.rtt > 0 {
		b.releaseTimer = time.AfterFunc(b.rtt, b.flushRelease)
	} else if b.releaseTimer == nil {
		b.flushReleaseS2CLocked()
	}
	b.mu.Unlock()
}

func (b *windowedPacketBridge) flushReleaseS2CLocked() {
	credit := b.pendingReleaseS2C
	b.pendingReleaseS2C = 0
	if credit > 0 {
		b.inflightS2C -= credit
		if b.inflightS2C < 0 {
			b.inflightS2C = 0
		}
		b.cond.Broadcast()
	}
}

func (b *windowedPacketBridge) flushReleaseLocked() {
	if b.releaseTimer != nil {
		b.releaseTimer.Stop()
		b.releaseTimer = nil
	}
	credit := b.pendingRelease
	b.pendingRelease = 0
	if credit > 0 {
		b.inflightC2S -= credit
		if b.inflightC2S < 0 {
			b.inflightC2S = 0
		}
		b.cond.Broadcast()
	}
	b.flushReleaseS2CLocked()
}

func (b *windowedPacketBridge) releaseC2S(n int) {
	b.mu.Lock()
	b.inflightC2S -= n
	if b.inflightC2S < 0 {
		b.inflightC2S = 0
	}
	b.cond.Broadcast()
	b.mu.Unlock()
}

func (b *windowedPacketBridge) closeBridge() {
	b.mu.Lock()
	b.closed = true
	b.flushReleaseLocked()
	b.cond.Broadcast()
	b.mu.Unlock()
}
