package client

import (
	"context"
	"net"
	"strconv"

	M "github.com/sagernet/sing/common/metadata"
)

// ListenPacket opens CONNECT-UDP over the current overlay (H3 datagram or H2 capsule).
func ListenPacket(host SessionUDP, ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	host.PreResolveDestinationHook()
	if ctxErr := host.CtxErr(ctx); ctxErr != nil {
		host.ClearHTTPFallbackAfterGiveUp()
		return nil, ctxErr
	}

	targetHost, err := host.ResolveDestination(destination)
	if err != nil {
		host.ClearHTTPFallbackAfterGiveUp()
		return nil, err
	}
	target := net.JoinHostPort(targetHost, strconv.Itoa(int(destination.Port)))

	udpClient, templateUDP, writeMax, _, err := host.PrepareUDP()
	if err != nil {
		host.ClearHTTPFallbackAfterGiveUp()
		return nil, err
	}

	conn, _, err := DialUDPResilient(ctx, host, udpClient, templateUDP, target)
	if err != nil {
		return nil, err
	}
	return host.WrapDatagramSplit(conn, writeMax, host.CurrentHTTPLayer()), nil
}
