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
// usque MaintainTunnel uses sync 1:1 ReadPacket→WritePacket on both loops. Prod host-kernel TUN KPI uses
// RunTunnelBatch (BatchTunnelDevice + read-ahead) as an upload extension — not a wire-pattern deviation.
//
// Ref: docs/masque/references/studies/usque/README.md (MaintainTunnel GO-1/GO-2)
// Target: docs/masque/architecture/CONNECT-IP-TARGET-ARCHITECTURE.md §3–4
type TunnelDevice interface {
	ReadPacket(ctx context.Context, buf []byte) (n int, err error)
	WritePacket(pkt []byte) error
	Close() error
}

// EgressSlot holds one accepted egress datagram from ReadEgressBatch (Buf pool slice + Len).
type EgressSlot struct {
	Buf []byte
	Len int
}

// BatchTunnelDevice extends TunnelDevice with upload DoD batch read (N≥2 pkts/LoopIn iter).
// Ref: docs/masque/architecture/CONNECT-IP-UPLOAD-BATCH-READ.md
type BatchTunnelDevice interface {
	TunnelDevice
	ReadEgressBatch(ctx context.Context, slots []EgressSlot, maxN int) (n int, err error)
}

// DefaultLoopInMaxBatch is the cap for one LoopIn batch read (H3 / coalesce-capable underlay).
const DefaultLoopInMaxBatch = 48

// H2HostKernelLoopInMaxBatch is the lab probe depth for H2 LoopIn A/B (not prod default).
// A/B 2026-07-22: 8 → UP flat; 1 → DOWN regress ~1400→500. Prod leaves DefaultLoopInMaxBatch.
const H2HostKernelLoopInMaxBatch = 8
