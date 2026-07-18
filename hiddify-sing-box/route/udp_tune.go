package route

import (
	"context"
	"net"

	"github.com/sagernet/sing-box/common/listener"
)

// TunedPacketListener wraps SOCKS5 UDP ASSOCIATE listen with tuned kernel UDP buffers.
// Prefer passing *listener.Listener (ListenPacket already tunes); this type remains for
// in-process test harnesses that do not use common/listener.Listener.
type TunedPacketListener struct{}

func (TunedPacketListener) ListenPacket(
	listenConfig net.ListenConfig,
	ctx context.Context,
	network, address string,
) (net.PacketConn, error) {
	pc, err := listenConfig.ListenPacket(ctx, network, address)
	if err != nil {
		return nil, err
	}
	listener.TuneUDPSocketBuffers(pc)
	return pc, nil
}

// TuneUDPPacketConn raises kernel UDP snd/rcv buffers on relay legs (exported for probes).
func TuneUDPPacketConn(conn any) {
	tuneUDPPacketConn(conn)
}

func tuneUDPPacketConn(conn any) {
	if conn == nil {
		return
	}
	if pc, ok := conn.(net.PacketConn); ok {
		listener.TuneUDPSocketBuffers(pc)
	}
	if up, ok := conn.(interface{ Upstream() any }); ok {
		tuneUDPPacketConn(up.Upstream())
	}
}
