package session

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"syscall"

	"github.com/quic-go/quic-go"
	mcip "github.com/sagernet/sing-box/transport/masque/connectip"
)

// ErrQUICPacketConnContract is returned when strict QUIC packet conn policy rejects a TierB conn.
var ErrQUICPacketConnContract = errors.New("quic transport packetconn contract violation")

// QUICPacketConnPolicy controls whether TierB packet conns may run in degraded mode.
type QUICPacketConnPolicy string

const (
	QUICPacketConnPolicyStrict     QUICPacketConnPolicy = "strict"
	QUICPacketConnPolicyPermissive QUICPacketConnPolicy = "permissive"
)

// QUICTransportPacketConnTier classifies packet conn capabilities for observability.
type QUICTransportPacketConnTier string

const (
	QUICTransportPacketConnTierA QUICTransportPacketConnTier = "TierA"
	QUICTransportPacketConnTierB QUICTransportPacketConnTier = "TierB"
)

// ReadQUICPacketConnPolicy reads MASQUE_QUIC_PACKET_CONN_POLICY (default permissive).
func ReadQUICPacketConnPolicy() QUICPacketConnPolicy {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("MASQUE_QUIC_PACKET_CONN_POLICY"))) {
	case "":
		return QUICPacketConnPolicyPermissive
	case string(QUICPacketConnPolicyPermissive):
		return QUICPacketConnPolicyPermissive
	default:
		return QUICPacketConnPolicyStrict
	}
}

// ValidateQUICTransportPacketConn enforces TierA capabilities when policy is strict.
func ValidateQUICTransportPacketConn(c net.PacketConn, path string) error {
	ok, connType, missing := quicPacketConnHasTierACapabilities(c)
	if ok {
		recordQUICTransportPacketConn(path, QUICTransportPacketConnTierA, connType, true)
		return nil
	}
	recordQUICTransportPacketConn(path, QUICTransportPacketConnTierB, connType, false)
	details := strings.Join(missing, ",")
	policy := ReadQUICPacketConnPolicy()
	if policy == QUICPacketConnPolicyPermissive {
		log.Printf("masque quic packetconn degraded mode path=%s policy=%s conn_type=%s missing=%s", path, policy, connType, details)
		return nil
	}
	return errors.Join(
		ErrQUICPacketConnContract,
		fmt.Errorf("path=%s policy=%s conn_type=%s missing=%s", path, policy, connType, details),
	)
}

// QuicDialWithPolicy wraps production or custom QUIC dial with packet conn tier recording.
func QuicDialWithPolicy(path string, customDial QUICDialFunc) QUICDialFunc {
	return func(ctx context.Context, addr string, tlsCfg *tls.Config, cfg *quic.Config) (*quic.Conn, error) {
		if customDial != nil {
			policy := ReadQUICPacketConnPolicy()
			if policy == QUICPacketConnPolicyStrict {
				recordQUICTransportPacketConn(path, QUICTransportPacketConnTierB, "custom_quic_dial", false)
				return nil, errors.Join(
					ErrQUICPacketConnContract,
					fmt.Errorf("path=%s policy=%s custom_quic_dial requires explicit degraded-mode opt-in", path, policy),
				)
			}
			recordQUICTransportPacketConn(path, QUICTransportPacketConnTierB, "custom_quic_dial", true)
			log.Printf("masque quic packetconn degraded mode path=%s policy=%s conn_type=%s", path, policy, "custom_quic_dial")
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
