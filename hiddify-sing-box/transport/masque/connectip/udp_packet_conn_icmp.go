package connectip

import (
	"net"
	"net/netip"
)

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
