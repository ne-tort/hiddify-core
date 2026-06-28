package connectip

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"time"
)

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
