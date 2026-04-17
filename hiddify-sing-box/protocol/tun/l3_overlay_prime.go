package tun

import (
	"net"

	"github.com/sagernet/sing-box/log"
)

// primeL3OverlayHandshake sends a zero-length UDP datagram on the overlay PacketConn.
// Outbounds that wrap sing-mux (and non-mux VLESS UDP) defer the first protocol write
// until WriteTo/WritePacket; the server then waits for that frame before it can call
// inbound NewPacketConnectionEx (e.g. l3router registerSession). Priming completes the
// client-side handshake so the hub registers the session before LAN/tun traffic.
func primeL3OverlayHandshake(logger log.ContextLogger, pConn net.PacketConn, udpAddr *net.UDPAddr) error {
	if pConn == nil || udpAddr == nil {
		return nil
	}
	_, err := pConn.WriteTo([]byte{}, udpAddr)
	if err != nil {
		return err
	}
	if logger != nil {
		logger.Info("l3 overlay: primed packet path (mux/vless handshake)")
	}
	return nil
}
