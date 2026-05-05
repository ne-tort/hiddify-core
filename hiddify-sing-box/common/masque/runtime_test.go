package masque

import (
	"context"
	"errors"
	"net"
	"testing"

	T "github.com/sagernet/sing-box/transport/masque"
	M "github.com/sagernet/sing/common/metadata"
)

type testIPSession struct{}

func (s *testIPSession) ReadPacket(buffer []byte) (int, error) { return 0, nil }
func (s *testIPSession) WritePacket(buffer []byte) ([]byte, error) {
	return nil, nil
}
func (s *testIPSession) Close() error { return nil }

type testSession struct {
	ip T.IPPacketSession
}

func (s *testSession) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	return nil, nil
}
func (s *testSession) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return nil, nil
}
func (s *testSession) OpenIPSession(ctx context.Context) (T.IPPacketSession, error) {
	return s.ip, nil
}
func (s *testSession) Capabilities() T.CapabilitySet { return T.CapabilitySet{ConnectIP: true} }
func (s *testSession) Close() error                  { return nil }

type testFactory struct {
	session T.ClientSession
}

func (f testFactory) NewSession(ctx context.Context, options T.ClientOptions) (T.ClientSession, error) {
	return f.session, nil
}

type errSessionFactory struct {
	err error
}

func (f errSessionFactory) NewSession(ctx context.Context, options T.ClientOptions) (T.ClientSession, error) {
	return nil, f.err
}

func TestRuntimeLastErrorOnStartFailure(t *testing.T) {
	rt := NewRuntime(errSessionFactory{err: errors.New("dial refused")}, RuntimeOptions{})
	if err := rt.Start(context.Background()); err == nil {
		t.Fatal("expected start error")
	}
	if rt.IsReady() {
		t.Fatal("expected not ready")
	}
	if rt.LifecycleState() != StateDegraded {
		t.Fatalf("lifecycle state: %v", rt.LifecycleState())
	}
	if rt.LastError() == nil {
		t.Fatal("expected LastError after failed Start")
	}
}

func TestRuntimeConnectIPStartOpensIPPlane(t *testing.T) {
	rt := NewRuntime(testFactory{session: &testSession{ip: &testIPSession{}}}, RuntimeOptions{
		TransportMode: "connect_ip",
	})
	if err := rt.Start(context.Background()); err != nil {
		t.Fatalf("start runtime: %v", err)
	}
	ip, err := rt.OpenIPSession(context.Background())
	if err != nil {
		t.Fatalf("open ip session: %v", err)
	}
	if ip == nil {
		t.Fatal("expected non-nil ip session")
	}
}

