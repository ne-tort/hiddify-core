package pump

import "context"

// PacketConn is the CONNECT-IP wire datagram session (ReadPacket / WritePacket + ICMP echo).
type PacketConn interface {
	ReadPacket(ctx context.Context, buf []byte) (int, error)
	WritePacket(buffer []byte) (icmp []byte, err error)
	Close() error
}

// TunnelDevice is the usque TunnelDevice contract: one userspace IP stack (gVisor TUN or connectip netstack).
// LoopIn reads egress IP frames from the device; LoopOut writes ingress IP frames into the device.
//
// Ref: docs/masque/references/studies/usque/README.md (MaintainTunnel GO-1/GO-2)
// Target: docs/masque/architecture/CONNECT-IP-TARGET-ARCHITECTURE.md §3–4
type TunnelDevice interface {
	ReadPacket(ctx context.Context, buf []byte) (n int, err error)
	WritePacket(pkt []byte) error
	Close() error
}
