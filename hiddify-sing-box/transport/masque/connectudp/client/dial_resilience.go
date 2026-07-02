package client

import (
	"context"
	"net"

	qmasque "github.com/quic-go/masque-go"
	"github.com/yosida95/uritemplate/v3"
)

// DialUDPResilient dials CONNECT-UDP with HTTP fallback, refresh-after-failure, and hop advance (M7 prod entry).
func DialUDPResilient(
	ctx context.Context,
	host SessionUDP,
	udpClient *qmasque.Client,
	template *uritemplate.Template,
	target string,
) (net.PacketConn, *qmasque.Client, error) {
	obs := host.ObservabilityInput(template, target)
	tryDial := func(client *qmasque.Client, tpl *uritemplate.Template) (net.PacketConn, error) {
		conn, err := DialAddr(ctx, host, obs, client, tpl, target)
		if err != nil && host.TryHTTPFallbackSwitch(err) {
			client, tpl = host.RewireUDPAfterFallback()
			conn, err = DialAddr(ctx, host, obs, client, tpl, target)
		}
		return conn, err
	}

	conn, err := tryDial(udpClient, template)
	if err == nil {
		return conn, udpClient, nil
	}

	udpClient, template = host.RefreshUDPAfterDialFailure(udpClient)
	conn, err = tryDial(udpClient, template)
	if err == nil {
		return conn, udpClient, nil
	}

	dialErr := err
	for {
		var resetErr error
		var advanced bool
		udpClient, template, advanced, resetErr = host.AdvanceHopAndPrepare()
		if !advanced {
			host.ClearHTTPFallbackAfterGiveUp()
			host.PreChainEndReturnHook()
			if ctxErr := host.CtxErr(ctx); ctxErr != nil {
				return nil, udpClient, host.JoinCtxCancel(dialErr, ctx)
			}
			return nil, udpClient, dialErr
		}
		if resetErr != nil {
			host.ClearHTTPFallbackAfterGiveUp()
			if ctxErr := host.CtxErr(ctx); ctxErr != nil {
				return nil, udpClient, host.JoinCtxCancel(resetErr, ctx)
			}
			return nil, udpClient, resetErr
		}
		conn, dialErr = tryDial(udpClient, template)
		if dialErr == nil {
			return conn, udpClient, nil
		}
	}
}
