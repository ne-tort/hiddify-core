package client

import (
	"context"
	"net"
	"strconv"

	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
)

// ErrConnectUDPNotSupported is returned when the backend capability set lacks CONNECT-UDP.
var ErrConnectUDPNotSupported = E.New("masque backend does not support CONNECT-UDP")

// ListenPacket opens CONNECT-UDP over the current overlay (H3 datagram or H2 capsule).
func ListenPacket(host ListenHost, ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
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

	udpClient, templateUDP, writeMax, httpLayer, err := host.PrepareUDP()
	if err != nil {
		host.ClearHTTPFallbackAfterGiveUp()
		return nil, err
	}

	conn, err := host.DialUDP(ctx, udpClient, templateUDP, target)
	if err != nil && host.TryHTTPFallbackSwitch(err) {
		udpClient, templateUDP = host.RewireUDPAfterFallback()
		conn, err = host.DialUDP(ctx, udpClient, templateUDP, target)
		if err == nil {
			return host.WrapDatagramSplit(conn, writeMax, host.CurrentHTTPLayer()), nil
		}
	}
	if err != nil {
		udpClient, templateUDP = host.RefreshUDPAfterDialFailure(udpClient)

		conn, err = host.DialUDP(ctx, udpClient, templateUDP, target)
		if err == nil {
			return host.WrapDatagramSplit(conn, writeMax, host.CurrentHTTPLayer()), nil
		}

		if err != nil && host.TryHTTPFallbackSwitch(err) {
			udpClient, templateUDP = host.RewireUDPAfterFallback()
			conn, err = host.DialUDP(ctx, udpClient, templateUDP, target)
			if err == nil {
				return host.WrapDatagramSplit(conn, writeMax, host.CurrentHTTPLayer()), nil
			}
		}

		dialErr := err
		for {
			var resetErr error
			var advanced bool
			udpClient, templateUDP, advanced, resetErr = host.AdvanceHopAndPrepare()
			if !advanced {
				host.ClearHTTPFallbackAfterGiveUp()
				host.PreChainEndReturnHook()
				if ctxErr := host.CtxErr(ctx); ctxErr != nil {
					return nil, host.JoinCtxCancel(dialErr, ctx)
				}
				return nil, dialErr
			}
			if resetErr != nil {
				host.ClearHTTPFallbackAfterGiveUp()
				if ctxErr := host.CtxErr(ctx); ctxErr != nil {
					return nil, host.JoinCtxCancel(resetErr, ctx)
				}
				return nil, resetErr
			}
			conn, dialErr = host.DialUDP(ctx, udpClient, templateUDP, target)
			if dialErr != nil && host.TryHTTPFallbackSwitch(dialErr) {
				udpClient, templateUDP = host.RewireUDPAfterFallback()
				conn, dialErr = host.DialUDP(ctx, udpClient, templateUDP, target)
			}
			if dialErr == nil {
				return host.WrapDatagramSplit(conn, writeMax, host.CurrentHTTPLayer()), nil
			}
		}
	}
	return host.WrapDatagramSplit(conn, writeMax, httpLayer), nil
}
