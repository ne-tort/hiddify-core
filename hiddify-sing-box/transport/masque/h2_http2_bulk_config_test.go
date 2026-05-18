package masque

import (
	"context"
	"crypto/tls"
	"net"
	"testing"
)

func TestMasqueBulkHTTP2ConfigReceiveWindows(t *testing.T) {
	cfg := masqueBulkHTTP2Config()
	if cfg == nil {
		t.Fatal("nil config")
	}
	if cfg.MaxReceiveBufferPerStream != masqueH2BulkStreamRecvWindow {
		t.Fatalf("stream recv=%d want %d", cfg.MaxReceiveBufferPerStream, masqueH2BulkStreamRecvWindow)
	}
	if cfg.MaxReceiveBufferPerConnection != masqueH2BulkConnRecvWindow {
		t.Fatalf("conn recv=%d want %d", cfg.MaxReceiveBufferPerConnection, masqueH2BulkConnRecvWindow)
	}
}

func TestNewMasqueBulkHTTP2TransportUsesBulkConfig(t *testing.T) {
	tr, err := newMasqueBulkHTTP2Transport(nil, func(ctx context.Context, network, addr string, cfg *tls.Config) (net.Conn, error) {
		return nil, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if tr == nil {
		t.Fatal("nil transport")
	}
	if tr.MaxReadFrameSize != masqueH2BulkMaxReadFrameSize {
		t.Fatalf("MaxReadFrameSize=%d want %d", tr.MaxReadFrameSize, masqueH2BulkMaxReadFrameSize)
	}
}
