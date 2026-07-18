package session

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"strings"
	"syscall"

	"github.com/quic-go/quic-go"
	mcip "github.com/sagernet/sing-box/transport/masque/connectip"
	h3t "github.com/sagernet/sing-box/transport/masque/h3"
)

// QUICTransportPacketConnTier classifies packet conn capabilities for observability.
type QUICTransportPacketConnTier string

const (
	QUICTransportPacketConnTierA QUICTransportPacketConnTier = "TierA"
	QUICTransportPacketConnTierB QUICTransportPacketConnTier = "TierB"
)

// ValidateQUICTransportPacketConn records TierA/TierB capabilities; TierB runs in degraded mode (prod normative).
func ValidateQUICTransportPacketConn(c net.PacketConn, path string) error {
	ok, connType, missing := quicPacketConnHasTierACapabilities(c)
	if ok {
		recordQUICTransportPacketConn(path, QUICTransportPacketConnTierA, connType, true)
		return nil
	}
	recordQUICTransportPacketConn(path, QUICTransportPacketConnTierB, connType, false)
	log.Printf("masque quic packetconn degraded mode path=%s conn_type=%s missing=%s", path, connType, strings.Join(missing, ","))
	return nil
}

// QuicDialWithPolicy wraps production or custom QUIC dial with packet conn tier recording.
// On success, registers the conn for masque-quic-stats.json (CONNECT-UDP uses custom_quic_dial
// and would otherwise bypass http3.Transport Dial hooks that call TrackQUICConn).
func QuicDialWithPolicy(path string, customDial QUICDialFunc) QUICDialFunc {
	return func(ctx context.Context, addr string, tlsCfg *tls.Config, cfg *quic.Config) (*quic.Conn, error) {
		var (
			conn *quic.Conn
			err  error
		)
		if customDial != nil {
			recordQUICTransportPacketConn(path, QUICTransportPacketConnTierB, "custom_quic_dial", true)
			log.Printf("masque quic packetconn degraded mode path=%s conn_type=%s", path, "custom_quic_dial")
			conn, err = customDial(ctx, addr, tlsCfg, cfg)
		} else {
			recordQUICTransportPacketConn(path, QUICTransportPacketConnTierA, "*net.UDPConn (quic.DialAddr)", true)
			conn, err = quic.DialAddr(ctx, addr, tlsCfg, cfg)
		}
		if err != nil {
			return nil, err
		}
		h3t.TrackQUICConn("client", conn)
		return conn, nil
	}
}

func quicPacketConnHasTierACapabilities(c net.PacketConn) (ok bool, connType string, missing []string) {
	connType = fmt.Sprintf("%T", c)
	if c == nil {
		return false, connType, []string{"packet_conn_nil"}
	}
	if _, yes := c.(interface{ SetReadBuffer(bytes int) error }); !yes {
		missing = append(missing, "SetReadBuffer")
	}
	if _, yes := c.(interface{ SetWriteBuffer(bytes int) error }); !yes {
		missing = append(missing, "SetWriteBuffer")
	}
	if _, yes := c.(interface {
		SyscallConn() (syscall.RawConn, error)
	}); !yes {
		missing = append(missing, "SyscallConn")
	}
	return len(missing) == 0, connType, missing
}

func recordQUICTransportPacketConn(path string, tier QUICTransportPacketConnTier, connType string, bufferTuningOK bool) {
	mcip.RecordQUICTransportPacketConn(path, string(tier), connType, bufferTuningOK)
}
