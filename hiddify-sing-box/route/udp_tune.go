package route

import (
	"context"
	"net"
)

const masqueRelayUDPSocketBuf = 4 << 20

// TunedPacketListener wraps SOCKS5 UDP ASSOCIATE listen with kernel 4 MiB buffers.
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
	tuneUDPPacketConn(pc)
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
		tuneUDPConn(pc)
	}
	if up, ok := conn.(interface{ Upstream() any }); ok {
		tuneUDPPacketConn(up.Upstream())
	}
}

func tuneUDPConn(pc net.PacketConn) {
	uc, ok := pc.(*net.UDPConn)
	if !ok {
		return
	}
	_ = uc.SetReadBuffer(masqueRelayUDPSocketBuf)
	_ = uc.SetWriteBuffer(masqueRelayUDPSocketBuf)
}
