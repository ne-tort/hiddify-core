package h3

import (
	"crypto/tls"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
)

func TestH3QUICPacketPlaneConfigIdleAndWindows(t *testing.T) {
	cfg := PacketPlaneQUICConfig(&quic.Config{})
	if cfg.MaxIdleTimeout != 24*time.Hour {
		t.Fatalf("MaxIdleTimeout: got %v want 24h", cfg.MaxIdleTimeout)
	}
	if cfg.KeepAlivePeriod != 15*time.Second {
		t.Fatalf("KeepAlivePeriod: got %v want 15s", cfg.KeepAlivePeriod)
	}
	if cfg.HandshakeIdleTimeout != 15*time.Second {
		t.Fatalf("HandshakeIdleTimeout: got %v want 15s", cfg.HandshakeIdleTimeout)
	}
	if cfg.InitialStreamReceiveWindow != defaultInitialStreamRecvWindow {
		t.Fatalf("InitialStreamReceiveWindow: got %d want %d", cfg.InitialStreamReceiveWindow, defaultInitialStreamRecvWindow)
	}
	if cfg.MaxConnectionReceiveWindow != defaultMaxConnectionRecvWindow {
		t.Fatalf("MaxConnectionReceiveWindow: got %d want %d", cfg.MaxConnectionReceiveWindow, defaultMaxConnectionRecvWindow)
	}
}

func TestH3QUICConnectStreamExperimentalCannotShrinkBulkFCFloor(t *testing.T) {
	base := TCPConnectStreamQUICConfig(QUICDialProfile{})
	// Simulate quic_experimental shrinking windows below P8 floor.
	base.InitialStreamReceiveWindow = 4096
	base.MaxStreamReceiveWindow = 4096
	base.InitialConnectionReceiveWindow = 8192
	base.MaxConnectionReceiveWindow = 8192

	FinalizeConnectStreamQUICConfig(base)
	if base.InitialStreamReceiveWindow < BulkStreamFCFloorBytes {
		t.Fatalf("InitialStreamReceiveWindow: got %d want >= P8 floor %d", base.InitialStreamReceiveWindow, BulkStreamFCFloorBytes)
	}
	if base.MaxStreamReceiveWindow < 128<<20 {
		t.Fatalf("MaxStreamReceiveWindow: got %d want prod boost >= %d", base.MaxStreamReceiveWindow, 128<<20)
	}
}

func TestH3QUICServerExperimentalCannotShrinkBulkFCFloor(t *testing.T) {
	cfg := HTTPServerQUICConfig()
	cfg.InitialStreamReceiveWindow = 4096
	cfg.MaxStreamReceiveWindow = 4096
	cfg.InitialConnectionReceiveWindow = 8192
	cfg.MaxConnectionReceiveWindow = 8192

	FinalizeConnectStreamQUICConfig(cfg)
	if cfg.InitialStreamReceiveWindow < BulkStreamFCFloorBytes {
		t.Fatalf("server InitialStreamReceiveWindow: got %d want >= P8 floor %d", cfg.InitialStreamReceiveWindow, BulkStreamFCFloorBytes)
	}
	if cfg.MaxStreamReceiveWindow < 128<<20 {
		t.Fatalf("server MaxStreamReceiveWindow: got %d want prod boost >= %d", cfg.MaxStreamReceiveWindow, 128<<20)
	}
}

func TestH3QUICConnectStreamAndServerWindowFloors(t *testing.T) {
	cli := TCPConnectStreamQUICConfig(QUICDialProfile{})
	if cli.InitialPacketSize != DefaultUDPInitialPacketSize {
		t.Fatalf("connect-stream InitialPacketSize: got %d want %d", cli.InitialPacketSize, DefaultUDPInitialPacketSize)
	}
	if cli.InitialStreamReceiveWindow < BulkStreamFCFloorBytes {
		t.Fatalf("connect-stream InitialStreamReceiveWindow: got %d want >= P8 floor %d", cli.InitialStreamReceiveWindow, BulkStreamFCFloorBytes)
	}
	if cli.InitialStreamReceiveWindow < 128<<20 {
		t.Fatalf("connect-stream InitialStreamReceiveWindow: got %d want >= %d", cli.InitialStreamReceiveWindow, 128<<20)
	}
	if cli.MaxStreamReceiveWindow < 128<<20 {
		t.Fatalf("connect-stream MaxStreamReceiveWindow: got %d want >= %d", cli.MaxStreamReceiveWindow, 128<<20)
	}
	if cli.InitialConnectionReceiveWindow < 192<<20 {
		t.Fatalf("connect-stream InitialConnectionReceiveWindow: got %d want >= %d", cli.InitialConnectionReceiveWindow, 192<<20)
	}
	if cli.MaxConnectionReceiveWindow < 192<<20 {
		t.Fatalf("connect-stream MaxConnectionReceiveWindow: got %d want >= %d", cli.MaxConnectionReceiveWindow, 192<<20)
	}
	cliWarp := TCPConnectStreamQUICConfig(QUICDialProfile{
		WarpMasqueClientCert: tls.Certificate{Certificate: [][]byte{[]byte("stub")}},
	})
	if cliWarp.InitialPacketSize != 0 {
		t.Fatalf("warp connect-stream InitialPacketSize: got %d want 0 (unset for Cloudflare path)", cliWarp.InitialPacketSize)
	}
	srv := HTTPServerQUICConfig()
	if srv.InitialPacketSize != DefaultUDPInitialPacketSize {
		t.Fatalf("server InitialPacketSize: got %d want %d", srv.InitialPacketSize, DefaultUDPInitialPacketSize)
	}
	if srv.InitialStreamReceiveWindow < 128<<20 {
		t.Fatalf("server InitialStreamReceiveWindow: got %d want >= %d", srv.InitialStreamReceiveWindow, 128<<20)
	}
}

func TestH3QUICConnectStreamEnableDatagrams(t *testing.T) {
	t.Run("generic_self_hosted_off", func(t *testing.T) {
		if TCPConnectStreamHTTP3EnableDatagrams(QUICDialProfile{}) {
			t.Fatal("expected datagrams disabled for generic self-hosted CONNECT-stream")
		}
	})
	t.Run("warp_mtls_on", func(t *testing.T) {
		opts := QUICDialProfile{
			WarpMasqueClientCert: tls.Certificate{Certificate: [][]byte{[]byte("x")}},
		}
		if !TCPConnectStreamHTTP3EnableDatagrams(opts) {
			t.Fatal("expected datagrams for warp mTLS")
		}
	})
	t.Run("cf_connect_ip", func(t *testing.T) {
		opts := QUICDialProfile{WarpConnectIPProtocol: "cf-connect-ip"}
		if !TCPConnectStreamHTTP3EnableDatagrams(opts) {
			t.Fatal("expected cf-connect-ip to enable datagrams")
		}
	})
}

func TestH3QUICConfigForDialPacketSize(t *testing.T) {
	cfg := QUICConfigForDial(QUICDialProfile{})
	if cfg.InitialPacketSize == 0 {
		t.Fatal("expected non-zero packet-plane initial packet size")
	}
	warp := QUICConfigForDial(QUICDialProfile{
		WarpMasqueClientCert: tls.Certificate{Certificate: [][]byte{[]byte("stub")}},
	})
	if warp.InitialPacketSize != 0 {
		t.Fatalf("warp packet-plane InitialPacketSize: got %d want 0", warp.InitialPacketSize)
	}
}

func TestTCPConnectStreamQUICConfigCongestionControl(t *testing.T) {
	reno := TCPConnectStreamQUICConfig(QUICDialProfile{})
	if reno.CongestionControl != quic.CongestionControlNewReno {
		t.Fatalf("default CongestionControl=%q want %q", reno.CongestionControl, quic.CongestionControlNewReno)
	}
	cubic := TCPConnectStreamQUICConfig(QUICDialProfile{CongestionControl: quic.CongestionControlCubic})
	if cubic.CongestionControl != quic.CongestionControlCubic {
		t.Fatalf("cubic CongestionControl=%q", cubic.CongestionControl)
	}
	srv := HTTPServerQUICConfig(quic.CongestionControlCubic)
	if srv.CongestionControl != quic.CongestionControlCubic {
		t.Fatalf("server cubic CongestionControl=%q", srv.CongestionControl)
	}
	if !quic.CongestionControlUseReno(reno.CongestionControl) {
		t.Fatal("new_reno should use Reno CA")
	}
	if quic.CongestionControlUseReno(cubic.CongestionControl) {
		t.Fatal("cubic should not use Reno CA")
	}
}
