package h2

import (
	"context"
	"crypto/tls"
	"net"
	"testing"
)

func TestBulkHTTP2ConfigReceiveWindows(t *testing.T) {
	cfg := bulkHTTP2Config()
	if cfg == nil {
		t.Fatal("nil config")
	}
	if cfg.MaxReceiveBufferPerStream != BulkStreamRecvWindow {
		t.Fatalf("stream recv=%d want %d", cfg.MaxReceiveBufferPerStream, BulkStreamRecvWindow)
	}
	if cfg.MaxReceiveBufferPerConnection != BulkConnRecvWindow {
		t.Fatalf("conn recv=%d want %d", cfg.MaxReceiveBufferPerConnection, BulkConnRecvWindow)
	}
}

func TestNewBulkHTTP2TransportUsesBulkConfig(t *testing.T) {
	tr, err := NewBulkHTTP2Transport(nil, func(ctx context.Context, network, addr string, cfg *tls.Config) (net.Conn, error) {
		return nil, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if tr == nil {
		t.Fatal("nil transport")
	}
	if tr.MaxReadFrameSize != BulkMaxReadFrameSize {
		t.Fatalf("MaxReadFrameSize=%d want %d", tr.MaxReadFrameSize, BulkMaxReadFrameSize)
	}
}
