package session

import (
	"testing"
	"time"
)

func TestApplyQUICExperimentalOptions(t *testing.T) {
	cfg := ApplyQUICExperimentalOptions(nil, QUICExperimentalOptions{
		Enabled:                    true,
		KeepAlivePeriod:            5 * time.Second,
		MaxIdleTimeout:             10 * time.Second,
		InitialStreamReceiveWindow: 1234,
		MaxIncomingStreams:         8,
	})
	if cfg.KeepAlivePeriod != 5*time.Second {
		t.Fatal("expected keepalive period to be applied")
	}
	if cfg.MaxIdleTimeout != 10*time.Second {
		t.Fatal("expected max idle timeout to be applied")
	}
	if cfg.InitialStreamReceiveWindow != 1234 {
		t.Fatal("expected stream window to be applied")
	}
	if cfg.MaxIncomingStreams != 8 {
		t.Fatal("expected max incoming streams to be applied")
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

func TestAuthorityHTTPServerQUICConfigDisablesDatagrams(t *testing.T) {
	serverCfg := HTTPServerQUICConfig()
	if serverCfg == nil || !serverCfg.EnableDatagrams {
		t.Fatal("expected default server QUIC config with datagram plane enabled")
	}
	authorityCfg := AuthorityHTTPServerQUICConfig()
	if authorityCfg == nil {
		t.Fatal("expected non-nil authority server quic config")
	}
	if authorityCfg.EnableDatagrams {
		t.Fatal("authority-only HTTP/3 listener must not enable QUIC datagrams")
	}
}
