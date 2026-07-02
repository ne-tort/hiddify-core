package masque

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	T "github.com/sagernet/sing-box/transport/masque"
	h3t "github.com/sagernet/sing-box/transport/masque/h3"
	M "github.com/sagernet/sing/common/metadata"
)

// TestRuntimeConnectStreamDialP8FloorAfterExperimental (A6-1): CoreClientFactory → Runtime → session
// CONNECT-stream dial must apply FinalizeConnectStreamQUICConfig after quic_experimental shrink.
func TestRuntimeConnectStreamDialP8FloorAfterExperimental(t *testing.T) {
	var captured *quic.Config

	targetLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen target: %v", err)
	}
	t.Cleanup(func() { _ = targetLn.Close() })
	targetPort := uint16(targetLn.Addr().(*net.TCPAddr).Port)

	proxyPort := startRuntimeInProcessTCPConnectProxy(t)

	rt := NewRuntime(T.CoreClientFactory{}, RuntimeOptions{
		Server:              "127.0.0.1",
		ServerPort:          uint16(proxyPort),
		MasqueQUICCryptoTLS: &tls.Config{InsecureSkipVerify: true},
		QUICExperimental: T.QUICExperimentalOptions{
			Enabled:                    true,
			InitialStreamReceiveWindow: 4096,
			MaxStreamReceiveWindow:     4096,
		},
		QUICDial: func(ctx context.Context, addr string, tlsCfg *tls.Config, cfg *quic.Config) (*quic.Conn, error) {
			captured = cfg.Clone()
			return nil, errors.New("masque: capture quic config")
		},
	})

	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	if err := rt.Start(ctx); err != nil {
		t.Fatalf("runtime start: %v", err)
	}
	t.Cleanup(func() { _ = rt.Close() })

	_, dialErr := rt.DialContext(ctx, "tcp", M.ParseSocksaddrHostPort("127.0.0.1", targetPort))
	if dialErr == nil {
		t.Fatal("expected dial error from capture hook")
	}
	if captured == nil {
		t.Fatal("QUICDial hook was not invoked — P8 Finalize path not exercised through Runtime")
	}
	if captured.InitialStreamReceiveWindow < h3t.BulkStreamFCFloorBytes {
		t.Fatalf("InitialStreamReceiveWindow: got %d want >= P8 floor %d",
			captured.InitialStreamReceiveWindow, h3t.BulkStreamFCFloorBytes)
	}
	if captured.MaxStreamReceiveWindow < 128<<20 {
		t.Fatalf("MaxStreamReceiveWindow: got %d want prod boost >= 128 MiB", captured.MaxStreamReceiveWindow)
	}
}
