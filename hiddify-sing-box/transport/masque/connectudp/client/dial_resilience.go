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
	dedicated := h3UsesDedicatedQUICClient(host)
	flowClient := udpClient
	if dedicated {
		flowClient = host.NewQUICClient()
	}
	fail := func(err error) (net.PacketConn, *qmasque.Client, error) {
		if dedicated && flowClient != nil {
			_ = flowClient.Close()
			return nil, nil, err
		}
		return nil, udpClient, err
	}
	refreshClient := func(prev *qmasque.Client) *qmasque.Client {
		if dedicated {
			return refreshDedicatedQUICClient(host, prev)
		}
		client, tpl := host.RefreshUDPAfterDialFailure(prev)
		template = tpl
		return client
	}

	obs := host.ObservabilityInput(template, target)
	tryDial := func(client *qmasque.Client, tpl *uritemplate.Template) (net.PacketConn, error) {
		conn, err := DialAddr(ctx, host, obs, client, tpl, target)
		if err != nil && host.TryHTTPFallbackSwitch(err) {
			client, tpl = host.RewireUDPAfterFallback()
			if dedicated {
				_ = flowClient.Close()
				dedicated = h3UsesDedicatedQUICClient(host)
				if dedicated {
					flowClient = host.NewQUICClient()
					client = flowClient
				} else {
					flowClient = client
				}
			}
			conn, err = DialAddr(ctx, host, obs, client, tpl, target)
		}
		return conn, err
	}
	success := func(conn net.PacketConn) (net.PacketConn, *qmasque.Client, error) {
		if dedicated {
			return wrapOwnedQUICPacketConn(conn, flowClient), nil, nil
		}
		return conn, flowClient, nil
	}

	conn, err := tryDial(flowClient, template)
	if err == nil {
		return success(conn)
	}

	flowClient = refreshClient(flowClient)
	conn, err = tryDial(flowClient, template)
	if err == nil {
		return success(conn)
	}

	dialErr := err
	for {
		var resetErr error
		var advanced bool
		var hopClient *qmasque.Client
		hopClient, template, advanced, resetErr = host.AdvanceHopAndPrepare()
		if !advanced {
			host.ClearHTTPFallbackAfterGiveUp()
			host.PreChainEndReturnHook()
			if ctxErr := host.CtxErr(ctx); ctxErr != nil {
				return fail(host.JoinCtxCancel(dialErr, ctx))
			}
			return fail(dialErr)
		}
		if resetErr != nil {
			host.ClearHTTPFallbackAfterGiveUp()
			if ctxErr := host.CtxErr(ctx); ctxErr != nil {
				return fail(host.JoinCtxCancel(resetErr, ctx))
			}
			return fail(resetErr)
		}
		if dedicated {
			flowClient = refreshDedicatedQUICClient(host, flowClient)
		} else {
			flowClient = hopClient
		}
		conn, dialErr = tryDial(flowClient, template)
		if dialErr == nil {
			return success(conn)
		}
	}
}
