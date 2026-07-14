package session

import (
	"testing"

	h3t "github.com/sagernet/sing-box/transport/masque/h3"
)

func TestFinalizeConnectStreamQUICConfigRestoresBulkFCFloor(t *testing.T) {
	base := TCPConnectStreamQUICConfig(ClientOptions{})
	cfg := base.Clone()
	cfg.InitialStreamReceiveWindow = 4096
	cfg.MaxStreamReceiveWindow = 4096
	h3t.FinalizeConnectStreamQUICConfig(cfg)
	if cfg.InitialStreamReceiveWindow < h3t.BulkStreamFCFloorBytes {
		t.Fatalf("InitialStreamReceiveWindow: got %d want >= P8 floor %d", cfg.InitialStreamReceiveWindow, h3t.BulkStreamFCFloorBytes)
	}
	if cfg.MaxStreamReceiveWindow < 128<<20 {
		t.Fatalf("MaxStreamReceiveWindow: got %d want prod boost", cfg.MaxStreamReceiveWindow)
	}
}

func TestQUICConfigForDialNonNil(t *testing.T) {
	cfg := QUICConfigForDial(ClientOptions{})
	if cfg == nil {
		t.Fatal("expected non-nil quic config")
	}
	if cfg.InitialPacketSize == 0 {
		t.Fatal("expected non-zero initial packet size baseline")
	}
}

func TestH3HTTPServerQUICConfigDisablesDatagrams(t *testing.T) {
	serverCfg := HTTPServerQUICConfig()
	if serverCfg == nil || !serverCfg.EnableDatagrams {
		t.Fatal("expected default server QUIC config with datagram plane enabled")
	}
	h3Cfg := H3HTTPServerQUICConfig()
	if h3Cfg == nil {
		t.Fatal("expected non-nil H3 server quic config")
	}
	if h3Cfg.EnableDatagrams {
		t.Fatal("standalone HTTP/3 listener must not enable QUIC datagrams")
	}
}
