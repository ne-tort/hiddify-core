package masque

import (
	"bufio"
	"context"
	"net"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/constant"
	boxsocks "github.com/sagernet/sing-box/protocol/socks"
	"github.com/sagernet/sing-box/route"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type directMasqueRouter struct {
	cm     *route.ConnectionManager
	dialer adapter.Outbound
}

func (r *directMasqueRouter) RouteConnection(ctx context.Context, conn net.Conn, metadata adapter.InboundContext) error {
	done := make(chan struct{})
	r.RouteConnectionEx(ctx, conn, metadata, N.OnceClose(func(error) { close(done) }))
	<-done
	return nil
}

func (r *directMasqueRouter) RouteConnectionEx(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	r.cm.NewConnection(ctx, r.dialer, conn, metadata, onClose)
}

func (r *directMasqueRouter) RoutePacketConnection(ctx context.Context, conn N.PacketConn, metadata adapter.InboundContext) error {
	done := make(chan struct{})
	r.RoutePacketConnectionEx(ctx, conn, metadata, N.OnceClose(func(error) { close(done) }))
	<-done
	return nil
}

func (r *directMasqueRouter) RoutePacketConnectionEx(ctx context.Context, conn N.PacketConn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	r.cm.NewPacketConnection(ctx, r.dialer, conn, metadata, onClose)
}

type masqueSessionOutbound struct {
	outbound.Adapter
	sess ClientSession
}

func (o *masqueSessionOutbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	return o.sess.DialContext(ctx, network, destination)
}

func (o *masqueSessionOutbound) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return o.sess.ListenPacket(ctx, destination)
}

func (o *masqueSessionOutbound) ResetConnectIPTCPAfterShortRelay() {
	if r, ok := o.sess.(interface{ ResetConnectIPTCPAfterShortRelay() }); ok {
		r.ResetConnectIPTCPAfterShortRelay()
	}
}

func (o *masqueSessionOutbound) WarmConnectIPTCPAfterShortRelay(ctx context.Context, dest M.Socksaddr) {
	if w, ok := o.sess.(interface {
		WarmConnectIPTCPAfterShortRelay(context.Context, M.Socksaddr)
	}); ok {
		w.WarmConnectIPTCPAfterShortRelay(ctx, dest)
	}
}

func startSocks5AssociateRelay(t *testing.T, router adapter.ConnectionRouterEx, inboundType string) uint16 {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen socks tcp: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	port := uint16(ln.Addr().(*net.TCPAddr).Port)

	upstream := adapter.NewRouteHandlerEx(adapter.InboundContext{
		Inbound:     "socks-in",
		InboundType: inboundType,
	}, router)

	go func() {
		for {
			conn, acceptErr := ln.Accept()
			if acceptErr != nil {
				return
			}
			go func(c net.Conn) {
				// RFC 1928: TCP close must tear down ASSOCIATE → CONNECT-UDP flow.
				_ = boxsocks.HandleConnectionExTCPBound(
					context.Background(),
					c,
					bufio.NewReader(c),
					nil,
					upstream,
					route.TunedPacketListener{},
					constant.UDPTimeout,
					M.SocksaddrFromNet(c.RemoteAddr()),
					nil,
				)
			}(conn)
		}
	}()
	time.Sleep(20 * time.Millisecond)
	return port
}
