package socks

// TCP-bound SOCKS5 UDP ASSOCIATE (RFC 1928 §7): association ends when the TCP
// control connection closes. Upstream sing.HandleConnectionEx hands the packet
// conn to the router and returns without watching TCP, so CONNECT-UDP flows
// otherwise linger until UDPTimeout (5m).

import (
	std_bufio "bufio"
	"context"
	"net"
	"sync"
	"time"

	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/auth"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	"github.com/sagernet/sing/common/canceler"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/protocol/socks"
	"github.com/sagernet/sing/protocol/socks/socks4"
	"github.com/sagernet/sing/protocol/socks/socks5"
)

// HandleConnectionExTCPBound matches socks.HandleConnectionEx, but UDP ASSOCIATE
// tears down the packet conn (and thus masque ListenPacket) when TCP closes.
func HandleConnectionExTCPBound(
	ctx context.Context,
	conn net.Conn,
	reader *std_bufio.Reader,
	authenticator *auth.Authenticator,
	handler socks.HandlerEx,
	packetListener socks.PacketListener,
	udpTimeout time.Duration,
	source M.Socksaddr,
	onClose N.CloseHandlerFunc,
) error {
	version, err := reader.ReadByte()
	if err != nil {
		return err
	}
	switch version {
	case socks4.Version:
		_ = reader.UnreadByte()
		return socks.HandleConnectionEx(ctx, conn, reader, authenticator, handler, packetListener, udpTimeout, source, onClose)
	case socks5.Version:
		return handleSocks5TCPBound(ctx, conn, reader, authenticator, handler, packetListener, udpTimeout, source, onClose)
	default:
		_ = reader.UnreadByte()
		return socks.HandleConnectionEx(ctx, conn, reader, authenticator, handler, packetListener, udpTimeout, source, onClose)
	}
}

func handleSocks5TCPBound(
	ctx context.Context,
	conn net.Conn,
	reader *std_bufio.Reader,
	authenticator *auth.Authenticator,
	handler socks.HandlerEx,
	packetListener socks.PacketListener,
	udpTimeout time.Duration,
	source M.Socksaddr,
	onClose N.CloseHandlerFunc,
) error {
	authRequest, err := socks5.ReadAuthRequest0(reader)
	if err != nil {
		return err
	}
	if authenticator != nil && !common.Contains(authRequest.Methods, socks5.AuthTypeUsernamePassword) {
		_ = socks5.WriteAuthResponse(conn, socks5.AuthResponse{Method: socks5.AuthTypeNoAcceptedMethods})
		return E.New("socks5: username/password required")
	}
	authMethod := socks5.AuthTypeNotRequired
	if authenticator != nil {
		authMethod = socks5.AuthTypeUsernamePassword
	}
	if err = socks5.WriteAuthResponse(conn, socks5.AuthResponse{Method: authMethod}); err != nil {
		return err
	}
	if authMethod == socks5.AuthTypeUsernamePassword {
		up, uerr := socks5.ReadUsernamePasswordAuthRequest(reader)
		if uerr != nil {
			return uerr
		}
		ctx = auth.ContextWithUser(ctx, up.Username)
		resp := socks5.UsernamePasswordAuthResponse{Status: socks5.UsernamePasswordStatusFailure}
		if authenticator.Verify(up.Username, up.Password) {
			resp.Status = socks5.UsernamePasswordStatusSuccess
		}
		if err = socks5.WriteUsernamePasswordAuthResponse(conn, resp); err != nil {
			return err
		}
		if resp.Status != socks5.UsernamePasswordStatusSuccess {
			return E.New("socks5: authentication failed, username=", up.Username)
		}
	}

	request, err := socks5.ReadRequest(reader)
	if err != nil {
		return err
	}
	switch request.Command {
	case socks5.CommandConnect:
		handler.NewConnectionEx(ctx, socks.NewLazyConn(conn, socks5.Version), source, request.Destination, onClose)
		return nil
	case socks5.CommandUDPAssociate:
		return acceptUDPAssociateTCPBound(ctx, conn, handler, packetListener, udpTimeout, source, onClose)
	default:
		_ = socks5.WriteResponse(conn, socks5.Response{ReplyCode: socks5.ReplyCodeUnsupported})
		return E.New("socks5: unsupported command ", request.Command)
	}
}

func acceptUDPAssociateTCPBound(
	ctx context.Context,
	conn net.Conn,
	handler socks.HandlerEx,
	packetListener socks.PacketListener,
	udpTimeout time.Duration,
	source M.Socksaddr,
	onClose N.CloseHandlerFunc,
) error {
	var (
		listenConfig net.ListenConfig
		udpConn      net.PacketConn
		err          error
	)
	if packetListener != nil {
		udpConn, err = packetListener.ListenPacket(listenConfig, ctx, M.NetworkFromNetAddr("udp", M.AddrFromNet(conn.LocalAddr())), M.SocksaddrFrom(M.AddrFromNet(conn.LocalAddr()), 0).String())
	} else {
		udpConn, err = listenConfig.ListenPacket(ctx, M.NetworkFromNetAddr("udp", M.AddrFromNet(conn.LocalAddr())), M.SocksaddrFrom(M.AddrFromNet(conn.LocalAddr()), 0).String())
	}
	if err != nil {
		return E.Cause(err, "socks5: listen udp")
	}
	err = socks5.WriteResponse(conn, socks5.Response{
		ReplyCode: socks5.ReplyCodeSuccess,
		Bind:      M.SocksaddrFromNet(udpConn.LocalAddr()).Unwrap(),
	})
	if err != nil {
		_ = udpConn.Close()
		return E.Cause(err, "socks5: write response")
	}

	var socksPacketConn N.PacketConn = socks.NewAssociatePacketConn(bufio.NewServerPacketConn(udpConn), M.Socksaddr{}, conn)
	socksPacketConn = newTCPBoundPacketConn(socksPacketConn, conn)

	if udpTimeout > 0 {
		_ = udpConn.SetReadDeadline(time.Now().Add(udpTimeout))
	}
	firstPacket := buf.NewPacket()
	destination, err := socksPacketConn.ReadPacket(firstPacket)
	if err != nil {
		_ = socksPacketConn.Close()
		return E.Cause(err, "socks5: read first packet")
	}
	if udpTimeout > 0 {
		_ = udpConn.SetReadDeadline(time.Time{})
	}
	if udpTimeout > 0 {
		ctx, socksPacketConn = canceler.NewPacketConn(ctx, socksPacketConn, udpTimeout)
	}
	socksPacketConn = bufio.NewCachedPacketConn(socksPacketConn, firstPacket, destination)
	handler.NewPacketConnectionEx(ctx, socksPacketConn, source, destination, onClose)
	return nil
}

// tcpBoundPacketConn closes the SOCKS UDP associate when the TCP control connection ends (RFC 1928).
type tcpBoundPacketConn struct {
	N.PacketConn
	tcp  net.Conn
	once sync.Once
}

func newTCPBoundPacketConn(pc N.PacketConn, tcp net.Conn) N.PacketConn {
	c := &tcpBoundPacketConn{PacketConn: pc, tcp: tcp}
	go func() {
		buf := make([]byte, 1)
		for {
			_, err := tcp.Read(buf)
			if err != nil {
				_ = c.Close()
				return
			}
		}
	}()
	return c
}

func (c *tcpBoundPacketConn) Close() error {
	var err error
	c.once.Do(func() {
		err = common.Close(c.PacketConn, c.tcp)
	})
	return err
}

func (c *tcpBoundPacketConn) Upstream() any {
	return c.PacketConn
}
