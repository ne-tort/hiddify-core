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

type udp4Tuple struct {
	srcAddr, dstAddr tcpip.Address
	srcPort, dstPort uint16
}

type udpForwardSession struct {
	f       *packetForwarder
	flow    udp4Tuple
	remote  *net.UDPConn
	origPkt []byte

	closeOnce   sync.Once
	pumpStarted atomic.Bool
}

func isUDPICMPUnreachable(n int, err error) bool {
	if err == nil {
		return false
	}
	return errors.Is(err, syscall.ECONNREFUSED) ||
		errors.Is(err, syscall.EHOSTUNREACH) ||
		errors.Is(err, syscall.ENETUNREACH)
}

func (f *packetForwarder) sendICMPPortUnreachable(origIP []byte) error {
	icmp := buildIPv4ICMPPortUnreachable(origIP)
	if len(icmp) == 0 {
		return nil
	}
	return f.writeRaw(icmp)
}

func (f *packetForwarder) dropUDPFlow(flow udp4Tuple) {
	f.uMu.Lock()
	s := f.udpSessions[flow]
	if s != nil {
		delete(f.udpSessions, flow)
	}
	f.uMu.Unlock()
	if s != nil && s.remote != nil {
		_ = s.remote.Close()
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

func (f *packetForwarder) handleUDPPacket(ctx context.Context, pkt []byte, iph header.IPv4) {
	if totalLen := int(iph.TotalLength()); totalLen >= header.IPv4MinimumSize && totalLen < len(pkt) {
		pkt = pkt[:totalLen]
		iph = header.IPv4(pkt)
	}
	ihl := int(pkt[0]&0x0f) * 4
	if ihl < header.IPv4MinimumSize || ihl+header.UDPMinimumSize > len(pkt) {
		return
	}
	udph := header.UDP(pkt[ihl:])
	udpLen := int(udph.Length())
	if udpLen < header.UDPMinimumSize || ihl+udpLen > len(pkt) {
		return
	}
	payload := pkt[ihl+header.UDPMinimumSize : ihl+udpLen]

	dstIP := netip.AddrFrom4(iph.DestinationAddress().As4())
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
		srcAddr: iph.SourceAddress(),
		dstAddr: iph.DestinationAddress(),
		srcPort: udph.SourcePort(),
		dstPort: dstPort,
	}

	s := f.getUDPSession(flow)
	if s == nil {
		dialAddr := DialAddr(dstIP, dstPort)
		remoteAddr, err := net.ResolveUDPAddr("udp", dialAddr)
		if err != nil {
			_ = f.sendICMPPortUnreachable(pkt)
			return
		}
		remote, err := f.o.Dialer.DialContext(ctx, "udp", remoteAddr.String())
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
	if _, err := s.remote.Write(payload); err != nil {
		if isUDPICMPUnreachable(0, err) {
			_ = f.sendICMPPortUnreachable(s.origPkt)
		}
		s.close()
	}
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
		readWait := 30 * time.Second
		if firstRead {
			readWait = udpForwarderICMPPoll
		}
		_ = s.remote.SetReadDeadline(time.Now().Add(readWait))
		n, err := s.remote.Read(buf)
		firstRead = false
		if n > 0 {
			src := netip.AddrFrom4(s.flow.dstAddr.As4())
			dst := netip.AddrFrom4(s.flow.srcAddr.As4())
			reply, buildErr := buildIPv4UDPPacket(src, s.flow.dstPort, dst, s.flow.srcPort, buf[:n])
			if buildErr != nil {
				return
			}
			if writeErr := s.f.writeRaw(reply); writeErr != nil {
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
				continue
			}
			return
		}
	}
}
