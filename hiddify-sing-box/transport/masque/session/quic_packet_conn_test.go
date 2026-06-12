package session

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
)

func TestValidateQUICTransportPacketConnTierAUDPConnPasses(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen packet: %v", err)
	}
	defer pc.Close()
	t.Setenv("MASQUE_QUIC_PACKET_CONN_POLICY", "strict")
	if err := ValidateQUICTransportPacketConn(pc, "test_server"); err != nil {
		t.Fatalf("expected TierA udp conn to pass strict policy, got: %v", err)
	}
}

func TestValidateQUICTransportPacketConnTierBStrictRejects(t *testing.T) {
	t.Setenv("MASQUE_QUIC_PACKET_CONN_POLICY", "strict")
	pc := &tierBPacketConnStub{}
	err := ValidateQUICTransportPacketConn(pc, "test_custom")
	if err == nil {
		t.Fatal("expected strict policy to reject TierB packet conn")
	}
	if !errors.Is(err, ErrQUICPacketConnContract) {
		t.Fatalf("expected ErrQUICPacketConnContract, got: %v", err)
	}
}

func TestQuicDialWithPolicyStrictRejectsCustomDial(t *testing.T) {
	t.Setenv("MASQUE_QUIC_PACKET_CONN_POLICY", "strict")
	dial := QuicDialWithPolicy("client_connect_stream", func(ctx context.Context, addr string, tlsCfg *tls.Config, cfg *quic.Config) (*quic.Conn, error) {
		t.Fatal("custom QUICDial must not run in strict mode")
		return nil, nil
	})
	_, err := dial(context.Background(), "127.0.0.1:443", &tls.Config{}, &quic.Config{})
	if err == nil {
		t.Fatal("expected strict policy reject error")
	}
	if !errors.Is(err, ErrQUICPacketConnContract) {
		t.Fatalf("expected ErrQUICPacketConnContract, got: %v", err)
	}
}

type tierBPacketConnStub struct{}

func (s *tierBPacketConnStub) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	return 0, &net.UDPAddr{}, io.EOF
}
func (s *tierBPacketConnStub) WriteTo(p []byte, addr net.Addr) (n int, err error) { return len(p), nil }
func (s *tierBPacketConnStub) Close() error                                       { return nil }
func (s *tierBPacketConnStub) LocalAddr() net.Addr                                { return &net.UDPAddr{} }
func (s *tierBPacketConnStub) SetDeadline(t time.Time) error                      { return nil }
func (s *tierBPacketConnStub) SetReadDeadline(t time.Time) error                  { return nil }
func (s *tierBPacketConnStub) SetWriteDeadline(t time.Time) error                 { return nil }
