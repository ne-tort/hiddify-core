package masque

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"

	connectip "github.com/quic-go/connect-ip-go"
	mcip "github.com/sagernet/sing-box/transport/masque/connectip"
	"github.com/sagernet/sing-box/transport/masque/session"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/yosida95/uritemplate/v3"
)

// TestConnectIPAbandonExitPathMatrix documents when ReleaseOpenedConnectIPSessionIfAbandoned
// must run after openIPSessionLocked succeeded but the consumer never receives plane state.
//
// | exit path                         | call site                    | abandon |
// |-----------------------------------|------------------------------|---------|
// | listenPacket ctx cancel post-open | dispatch_bridge.go:120-124   | yes     |
// | dial_tcp netstack factory error   | connectip/dial_tcp.go:71     | yes     |
// | listenPacket / dial_tcp success   | consumer attaches PacketConn | no      |
func TestConnectIPAbandonExitPathMatrix(t *testing.T) {
	okConn := testStubConnectIPConn()

	t.Run("listenPacket_cancel_after_open", func(t *testing.T) {
		templateIP, err := uritemplate.New("https://example.com/masque/ip")
		if err != nil {
			t.Fatalf("build ip template: %v", err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		s := newTestCoreSession(session.CoreSession{
			Options:    ClientOptions{TransportMode: "connect_ip"},
			TemplateIP: templateIP,
			Caps:       CapabilitySet{ConnectIP: true},
		})
		cs := &coreSession{
			CoreSession: s.CoreSession,
			dialConnectIPAttemptHook: func(context.Context, bool) (*connectip.Conn, error) {
				return okConn, nil
			},
			listenPacketPostOpenIPSessionUnlockHook: cancel,
		}
		_, listenErr := cs.ListenPacket(ctx, M.Socksaddr{})
		if listenErr == nil || !errors.Is(listenErr, context.Canceled) {
			t.Fatalf("expected context.Canceled, got %v", listenErr)
		}
		if cs.IPConn != nil {
			t.Fatal("expected ipConn cleared after listenPacket abandon")
		}
	})

	t.Run("dial_tcp_factory_error", func(t *testing.T) {
		var releaseCount atomic.Int32
		host := &abandonMatrixDialTCPHost{
			openSession: okConn,
			factoryErr:  errors.New("factory down"),
			onRelease: func() {
				releaseCount.Add(1)
			},
		}
		_, err := mcip.DialTCP(context.Background(), host, M.ParseSocksaddrHostPort("127.0.0.1", 443))
		if err == nil || err.Error() != "factory down" {
			t.Fatalf("expected factory error, got %v", err)
		}
		if releaseCount.Load() != 1 {
			t.Fatalf("releaseAbandoned=%d want 1", releaseCount.Load())
		}
	})

	t.Run("listenPacket_success_keeps_session", func(t *testing.T) {
		templateIP, err := uritemplate.New("https://example.com/masque/ip")
		if err != nil {
			t.Fatalf("build ip template: %v", err)
		}
		s := newTestCoreSession(session.CoreSession{
			Options:    ClientOptions{TransportMode: "connect_ip"},
			TemplateIP: templateIP,
			Caps:       CapabilitySet{ConnectIP: true},
		})
		cs := &coreSession{
			CoreSession: s.CoreSession,
			dialConnectIPAttemptHook: func(context.Context, bool) (*connectip.Conn, error) {
				return okConn, nil
			},
		}
		pc, listenErr := cs.ListenPacket(context.Background(), M.Socksaddr{})
		if listenErr != nil {
			t.Fatalf("unexpected listen error: %v", listenErr)
		}
		if pc == nil {
			t.Fatal("expected PacketConn")
		}
		_ = pc.Close()
		if cs.IPConn == nil {
			t.Fatal("expected ipConn retained on successful listenPacket (no abandon)")
		}
	})
}

type abandonMatrixDialTCPHost struct {
	openSession *connectip.Conn
	openErr     error
	factoryErr  error
	onRelease   func()
}

func (h *abandonMatrixDialTCPHost) ClearHTTPFallbackAfterGiveUp() {}

func (h *abandonMatrixDialTCPHost) LockSession()   {}
func (h *abandonMatrixDialTCPHost) UnlockSession() {}

func (h *abandonMatrixDialTCPHost) OpenIPSessionLocked(context.Context) (mcip.PacketSession, error) {
	if h.openErr != nil {
		return nil, h.openErr
	}
	return abandonMatrixPacketSession{conn: h.openSession}, nil
}

func (h *abandonMatrixDialTCPHost) TCPNetstack() mcip.TCPNetstack { return nil }

func (h *abandonMatrixDialTCPHost) AttachTCPNetstack(mcip.TCPNetstack) {}

func (h *abandonMatrixDialTCPHost) ResetStaleConnectIPPlaneLocked() {}

func (h *abandonMatrixDialTCPHost) FlushTCPNetstackIngress(mcip.TCPNetstack) {}

func (h *abandonMatrixDialTCPHost) BumpTCPInstallInflight(int) {}

func (h *abandonMatrixDialTCPHost) MaybeStartConnectIPIngressLocked() {}

func (h *abandonMatrixDialTCPHost) NewTCPNetstack(context.Context, mcip.PacketSession) (mcip.TCPNetstack, error) {
	return nil, h.factoryErr
}

func (h *abandonMatrixDialTCPHost) OnTCPNetstackFactoryError() {}

func (h *abandonMatrixDialTCPHost) RecordTCPNetstackReady(bool) {}

func (h *abandonMatrixDialTCPHost) ReleaseAbandonedIPSession() {
	if h.onRelease != nil {
		h.onRelease()
	}
}

type abandonMatrixPacketSession struct {
	conn *connectip.Conn
}

func (s abandonMatrixPacketSession) ReadPacket([]byte) (int, error)       { return 0, errors.New("stub") }
func (s abandonMatrixPacketSession) WritePacket([]byte) ([]byte, error)  { return nil, errors.New("stub") }
func (s abandonMatrixPacketSession) Close() error                       { return nil }
