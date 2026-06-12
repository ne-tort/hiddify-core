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
	if cfg.InitialStreamReceiveWindow != defaultInitialStreamRecvWindow {
		t.Fatalf("InitialStreamReceiveWindow: got %d want %d", cfg.InitialStreamReceiveWindow, defaultInitialStreamRecvWindow)
	}
	if cfg.MaxConnectionReceiveWindow != defaultMaxConnectionRecvWindow {
		t.Fatalf("MaxConnectionReceiveWindow: got %d want %d", cfg.MaxConnectionReceiveWindow, defaultMaxConnectionRecvWindow)
	}
}

func TestH3QUICConnectStreamAndServerWindowFloors(t *testing.T) {
	cli := TCPConnectStreamQUICConfig(QUICDialProfile{})
	if cli.InitialPacketSize != DefaultUDPInitialPacketSize {
		t.Fatalf("connect-stream InitialPacketSize: got %d want %d", cli.InitialPacketSize, DefaultUDPInitialPacketSize)
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
	t.Run("legacy_env", func(t *testing.T) {
		t.Setenv("HIDDIFY_MASQUE_TCP_HTTP3_LEGACY_DATAGRAMS", "1")
		if !TCPConnectStreamHTTP3EnableDatagrams(QUICDialProfile{}) {
			t.Fatal("expected legacy env to enable datagrams")
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
