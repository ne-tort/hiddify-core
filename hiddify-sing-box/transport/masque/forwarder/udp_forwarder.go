package forwarder

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/sagernet/gvisor/pkg/tcpip"
	"github.com/sagernet/gvisor/pkg/tcpip/header"
)

const udpForwarderReadBuf = 64 * 1024

// udpForwarderICMPPoll waits briefly after an onward UDP write for kernel ICMP
// (e.g. dig to a TCP-only port) before the client probe times out.
const udpForwarderICMPPoll = 400 * time.Millisecond

// udpSessionIdle closes an S2 UDP session after no client→server datagrams.
// P4-5: onward flood sinks keep pumping S2C after the client stops; without C2S idle
// teardown the orphan pump poisons WAN multi-run on a sticky dual process.
// Do NOT stopPlaneFromEgress on per-session idle — a short-lived flow (bench smoke)
// must not tear down the CONNECT-IP route under a concurrent bulk session.
// KPI measure_udp always sends C2S while measuring, so idle does not fire mid-test.
const udpSessionIdle = 3 * time.Second

type udp4Tuple struct {
	srcAddr, dstAddr tcpip.Address
	srcPort, dstPort uint16
}

type udpForwardSession struct {
	f       *packetForwarder
	flow    udp4Tuple
	remote  *net.UDPConn
	origPkt []byte

	closeOnce       sync.Once
	pumpStarted     atomic.Bool
	lastC2SUnixNano atomic.Int64
}

func isUDPICMPUnreachable(n int, err error) bool {
	if err == nil {
		return false
	}
	return errors.Is(err, syscall.ECONNREFUSED) ||
		errors.Is(err, syscall.EHOSTUNREACH) ||
		errors.Is(err, syscall.ENETUNREACH)
}

func (f *packetForwarder) dropUDPFlow(flow udp4Tuple) {
	f.uMu.Lock()
	s := f.udpSessions[flow]
	if s != nil {
		delete(f.udpSessions, flow)
	}
	udpLeft := len(f.udpSessions)
	f.uMu.Unlock()
	if s != nil && s.remote != nil {
		_ = s.remote.Close()
	}
	if udpLeft == 0 {
		f.maybeStopPlaneIfNoSessions()
	}
}

// maybeStopPlaneIfNoSessions closes the packet conn when S2 has no TCP/UDP sessions left.
// Safe with concurrent flows: a smoke UDP idle-close while bulk UDP/TCP lives leaves udpLeft>0
// or tcpLeft>0. After client kill, the last orphan idle-close ends the half-dead route (P4-5).
func (f *packetForwarder) maybeStopPlaneIfNoSessions() {
	f.sMu.Lock()
	tcpLeft := len(f.sessions)
	f.sMu.Unlock()
	f.uMu.Lock()
	udpLeft := len(f.udpSessions)
	f.uMu.Unlock()
	if tcpLeft == 0 && udpLeft == 0 {
		f.stopPlaneFromEgress()
	}
}

func (f *packetForwarder) getUDPSession(flow udp4Tuple) *udpForwardSession {
	f.uMu.Lock()
	defer f.uMu.Unlock()
	return f.udpSessions[flow]
}

func (f *packetForwarder) addUDPSession(flow udp4Tuple, s *udpForwardSession) {
	f.uMu.Lock()
	if f.udpSessions == nil {
		f.udpSessions = make(map[udp4Tuple]*udpForwardSession)
	}
	f.udpSessions[flow] = s
	f.uMu.Unlock()
}

func (s *udpForwardSession) close() {
	s.closeOnce.Do(func() {
		s.f.dropUDPFlow(s.flow)
	})
}

func (s *udpForwardSession) noteC2S() {
	s.lastC2SUnixNano.Store(time.Now().UnixNano())
}

func (s *udpForwardSession) c2sIdleExpired() bool {
	last := s.lastC2SUnixNano.Load()
	if last == 0 {
		return false
	}
	return time.Since(time.Unix(0, last)) > udpSessionIdle
}

// enqueueDownloadRespectingIdle pipelines S2C while still honouring C2S idle and ctx cancel.
// A plain blocking enqueueDownload lets a dead peer fill downloadCh and park the pump forever,
// so the read loop never observes idle and the onward UDP FD stays open (P4-5 sticky dual).
func (s *udpForwardSession) enqueueDownloadRespectingIdle(ctx context.Context, pkt []byte) error {
	if len(pkt) == 0 {
		return nil
	}
	f := s.f
	if f.downloadCh == nil {
		err := f.sendPacketNow(pkt)
		returnPacket(pkt)
		return err
	}
	for {
		if s.c2sIdleExpired() {
			returnPacket(pkt)
			return net.ErrClosed
		}
		select {
		case <-ctx.Done():
			returnPacket(pkt)
			return ctx.Err()
		case <-f.downloadStopped:
			returnPacket(pkt)
			return net.ErrClosed
		case f.downloadCh <- pkt:
			f.o.DownloadQueueMetrics.noteEnqueued()
			return nil
		case <-time.After(50 * time.Millisecond):
		}
	}
}

func (f *packetForwarder) handleUDPPacket(ctx context.Context, pkt []byte, iph header.IPv4) {
	if totalLen := int(iph.TotalLength()); totalLen >= header.IPv4MinimumSize && totalLen < len(pkt) {
		pkt = pkt[:totalLen]
	}
	ihl := int(pkt[0]&0x0f) * 4
	if ihl < header.IPv4MinimumSize || ihl+header.UDPMinimumSize > len(pkt) {
		return
	}
	f.handleUDPPacketAt(ctx, pkt, ihl)
}

func (f *packetForwarder) handleUDPPacketAt(ctx context.Context, pkt []byte, l4Off int) {
	if l4Off+header.UDPMinimumSize > len(pkt) {
		return
	}
	udph := header.UDP(pkt[l4Off:])
	udpLen := int(udph.Length())
	if udpLen < header.UDPMinimumSize || l4Off+udpLen > len(pkt) {
		return
	}
	payload := pkt[l4Off+header.UDPMinimumSize : l4Off+udpLen]

	var srcAddr, dstAddr tcpip.Address
	if len(pkt) >= header.IPv6MinimumSize && pkt[0]>>4 == 6 {
		iph := header.IPv6(pkt)
		srcAddr = iph.SourceAddress()
		dstAddr = iph.DestinationAddress()
	} else {
		iph := header.IPv4(pkt)
		srcAddr = iph.SourceAddress()
		dstAddr = iph.DestinationAddress()
	}

	dstIP := netipFromTCPip(dstAddr)
	if err := allowDestIP(dstIP, f.o.AllowPrivateTargets); err != nil {
		_ = f.sendICMPPortUnreachable(pkt)
		return
	}
	dstPort := udph.DestinationPort()
	if !allowPort(dstPort, f.o.AllowedTargetPorts, f.o.BlockedTargetPorts) {
		_ = f.sendICMPPortUnreachable(pkt)
		return
	}

	flow := udp4Tuple{
		srcAddr: srcAddr,
		dstAddr: dstAddr,
		srcPort: udph.SourcePort(),
		dstPort: dstPort,
	}

	s := f.getUDPSession(flow)
	if s == nil {
		dialAddr := DialAddr(dstIP, dstPort)
		remoteAddr, err := net.ResolveUDPAddr(udpNetwork(dstIP), dialAddr)
		if err != nil {
			_ = f.sendICMPPortUnreachable(pkt)
			return
		}
		remote, err := f.o.Dialer.DialContext(ctx, udpNetwork(dstIP), remoteAddr.String())
		if err != nil {
			_ = f.sendICMPPortUnreachable(pkt)
			return
		}
		udpConn, ok := remote.(*net.UDPConn)
		if !ok {
			_ = remote.Close()
			_ = f.sendICMPPortUnreachable(pkt)
			return
		}
		s = &udpForwardSession{
			f:       f,
			flow:    flow,
			remote:  udpConn,
			origPkt: append([]byte(nil), pkt...),
		}
		s.noteC2S()
		f.addUDPSession(flow, s)
		if len(payload) > 0 {
			if _, err := s.remote.Write(payload); err != nil {
				if isUDPICMPUnreachable(0, err) {
					_ = f.sendICMPPortUnreachable(pkt)
				}
				s.close()
				return
			}
		}
		if s.pumpStarted.CompareAndSwap(false, true) {
			go s.pumpRemoteToClient(ctx)
		}
		return
	}

	if len(payload) == 0 {
		return
	}
	s.noteC2S()
	if _, err := s.remote.Write(payload); err != nil {
		if isUDPICMPUnreachable(0, err) {
			_ = f.sendICMPPortUnreachable(s.origPkt)
		}
		s.close()
	}
}

func udpNetwork(dst netip.Addr) string {
	if dst.Is6() && !dst.Is4In6() {
		return "udp6"
	}
	return "udp"
}

func (s *udpForwardSession) pumpRemoteToClient(ctx context.Context) {
	defer s.close()
	buf := make([]byte, udpForwarderReadBuf)
	firstRead := true
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		if s.c2sIdleExpired() {
			return
		}
		readWait := 30 * time.Second
		if firstRead {
			readWait = udpForwarderICMPPoll
		}
		// Cap read wait so C2S idle is observed promptly under onward flood.
		if readWait > udpSessionIdle {
			readWait = udpSessionIdle
		}
		_ = s.remote.SetReadDeadline(time.Now().Add(readWait))
		n, err := s.remote.Read(buf)
		firstRead = false
		if n > 0 {
			if s.c2sIdleExpired() {
				return
			}
			src := netipFromTCPip(s.flow.dstAddr)
			dst := netipFromTCPip(s.flow.srcAddr)
			reply, buildErr := buildIPUDPPacket(src, dst, s.flow.dstPort, s.flow.srcPort, buf[:n])
			if buildErr != nil {
				return
			}
			// P4-3: UDP S2C is bulk DATA — use downloadCh (8192), not writeCh (512 control).
			// writeRaw blocked pumpRemoteToClient under WAN RTT → helper sendto OK, client DOWN≪target.
			// P4-5: must not block forever on a full downloadCh — that skips C2S-idle checks and
			// leaves orphan onward UDP sockets (Recv-Q fill) poisoning sticky dual WAN DOWN.
			if writeErr := s.enqueueDownloadRespectingIdle(ctx, reply); writeErr != nil {
				return
			}
		}
		if err != nil {
			if isUDPICMPUnreachable(n, err) {
				_ = s.f.sendICMPPortUnreachable(s.origPkt)
				return
			}
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() {
				if s.c2sIdleExpired() {
					return
				}
				continue
			}
			return
		}
	}
}
