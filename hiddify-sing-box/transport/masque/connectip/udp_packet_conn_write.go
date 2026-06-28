package connectip

import (
	"errors"
	"net"
	"os"
)

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
