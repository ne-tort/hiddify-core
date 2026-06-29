package session

import (
	"context"
	"crypto/tls"
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
	if err := ValidateQUICTransportPacketConn(pc, "test_server"); err != nil {
		t.Fatalf("expected TierA udp conn to pass, got: %v", err)
	}
}

func TestValidateQUICTransportPacketConnTierBPermissivePasses(t *testing.T) {
	pc := &tierBPacketConnStub{}
	if err := ValidateQUICTransportPacketConn(pc, "test_custom"); err != nil {
		t.Fatalf("expected TierB degraded mode to pass, got: %v", err)
	}
}

func TestQuicDialWithPolicyCustomDialRuns(t *testing.T) {
	var ran bool
	dial := QuicDialWithPolicy("client_connect_stream", func(ctx context.Context, addr string, tlsCfg *tls.Config, cfg *quic.Config) (*quic.Conn, error) {
		ran = true
		return nil, nil
	})
	_, _ = dial(context.Background(), "127.0.0.1:443", &tls.Config{}, &quic.Config{})
	if !ran {
		t.Fatal("expected custom QUICDial to run in prod degraded mode")
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
