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
func QuicDialWithPolicy(path string, customDial QUICDialFunc) QUICDialFunc {
	return func(ctx context.Context, addr string, tlsCfg *tls.Config, cfg *quic.Config) (*quic.Conn, error) {
		if customDial != nil {
			recordQUICTransportPacketConn(path, QUICTransportPacketConnTierB, "custom_quic_dial", true)
			log.Printf("masque quic packetconn degraded mode path=%s conn_type=%s", path, "custom_quic_dial")
			return customDial(ctx, addr, tlsCfg, cfg)
		}
		recordQUICTransportPacketConn(path, QUICTransportPacketConnTierA, "*net.UDPConn (quic.DialAddr)", true)
		return quic.DialAddr(ctx, addr, tlsCfg, cfg)
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
