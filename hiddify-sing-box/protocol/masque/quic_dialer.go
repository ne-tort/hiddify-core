package masque

import (
	"context"
	"crypto/tls"
	"encoding/hex"
	"io"
	"log"
	"net"
	"os"
	"reflect"
	"strings"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/option"
	TM "github.com/sagernet/sing-box/transport/masque"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

var newQUICOutboundDialer = dialer.New

func buildQUICDialFunc(ctx context.Context, options option.DialerOptions, remoteIsDomain bool) (TM.QUICDialFunc, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	var (
		outboundDialer N.Dialer
		err            error
	)
	func() {
		defer func() {
			if r := recover(); r != nil {
				outboundDialer = nil
				err = E.New("dialer.New panic: ", r)
			}
		}()
		outboundDialer, err = newQUICOutboundDialer(ctx, options, remoteIsDomain)
	}()
	if err != nil {
		if reflect.DeepEqual(options, option.DialerOptions{}) {
			return nil, nil
		}
		return nil, E.Cause(err, "initialize MASQUE QUIC dialer")
	}
	if outboundDialer == nil {
		return nil, E.New("initialize MASQUE QUIC dialer: got nil dialer")
	}
	return func(ctx context.Context, address string, tlsConf *tls.Config, quicConf *quic.Config) (*quic.Conn, error) {
		destination := M.ParseSocksaddr(address)
		if !destination.IsValid() {
			return nil, E.New("invalid MASQUE server address: ", address)
		}
		conn, err := outboundDialer.DialContext(ctx, N.NetworkUDP, destination)
		if err != nil {
			return nil, err
		}
		// sing-box UDP dial returns a *connected* UDP socket. quic.Transport uses WriteTo on its
		// PacketConn, which panics/fails on connected *net.UDPConn ("use of WriteTo with pre-connected connection").
		// Tier A (raw *net.UDPConn) is only valid for an *unconnected* datagram socket — not this path.
		packetConn := &connectedPacketConn{Conn: conn, remoteAddr: conn.RemoteAddr()}
		transport := &quic.Transport{Conn: packetConn}
		earlyConn, err := transport.Dial(ctx, conn.RemoteAddr(), tlsConf, quicConf)
		if err != nil {
			_ = conn.Close()
			return nil, err
		}
		return earlyConn, nil
	}, nil
}

type connectedPacketConn struct {
	net.Conn
	remoteAddr net.Addr
}

func (c *connectedPacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	n, err = c.Conn.Read(p)
	if err != nil {
		return 0, nil, err
	}
	log.Printf("masque quic_dialer read_from bytes=%d remote=%v", n, c.remoteAddr)
	if os.Getenv("HIDDIFY_MASQUE_QUIC_HEX_SMALL_READS") == "1" && n > 0 && n <= 64 {
		log.Printf("masque quic_dialer small_read hex=%s", strings.ToUpper(hex.EncodeToString(p[:n])))
	}
	return n, c.remoteAddr, nil
}

func (c *connectedPacketConn) WriteTo(p []byte, _ net.Addr) (n int, err error) {
	log.Printf("masque quic_dialer write_to bytes=%d remote=%v", len(p), c.remoteAddr)
	return c.Conn.Write(p)
}

func (c *connectedPacketConn) LocalAddr() net.Addr {
	return c.Conn.LocalAddr()
}

func (c *connectedPacketConn) SetDeadline(t time.Time) error {
	return c.Conn.SetDeadline(t)
}

func (c *connectedPacketConn) SetReadDeadline(t time.Time) error {
	return c.Conn.SetReadDeadline(t)
}

func (c *connectedPacketConn) SetWriteDeadline(t time.Time) error {
	return c.Conn.SetWriteDeadline(t)
}

func (c *connectedPacketConn) Close() error {
	if c.Conn == nil {
		return nil
	}
	err := c.Conn.Close()
	if err != nil && err != io.EOF {
		return err
	}
	return nil
}
