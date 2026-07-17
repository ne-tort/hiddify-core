package h2

import (
	"context"
	"crypto/tls"
	"net"
	"testing"
	"time"
)

func TestDefaultSettings(t *testing.T) {
	p := Resolve(Tuning{})
	if p.StreamRecvWindow != DefaultStreamRecvWindow || p.ConnRecvWindow != DefaultConnRecvWindow {
		t.Fatalf("windows stream=%d conn=%d", p.StreamRecvWindow, p.ConnRecvWindow)
	}
	if p.MaxReadFrameSize != DefaultMaxReadFrameSize || p.MaxConcurrentStreams != DefaultMaxConcurrentStreams {
		t.Fatalf("frame=%d mcs=%d", p.MaxReadFrameSize, p.MaxConcurrentStreams)
	}
	if p.ReadIdleTimeout != DefaultReadIdleTimeout {
		t.Fatalf("idle=%v", p.ReadIdleTimeout)
	}
	if p.UploadFlushBytes != DefaultUploadFlushBytes || p.UploadPipeBytes != DefaultUploadPipeBytes {
		t.Fatalf("flush=%d pipe=%d", p.UploadFlushBytes, p.UploadPipeBytes)
	}
	if p.DownloadBufferBytes != DefaultDownloadBufferBytes || p.DownloadFillWait != DefaultDownloadFillWait {
		t.Fatalf("download buf=%d wait=%v", p.DownloadBufferBytes, p.DownloadFillWait)
	}
}

func TestResolveTuningOverrides(t *testing.T) {
	p := Resolve(Tuning{
		MaxConcurrentStreams:  500,
		MaxReadFrameSize:      32 << 10,
		UploadFlushBytes:      32 << 10,
		UploadPipeBytes:       64 << 10,
		DownloadBufferBytes:   1 << 20,
		DownloadFillWait:      5 * time.Millisecond,
		DownloadFlushMinBytes: 128 << 10,
		DownloadFillMaxWall:   20 * time.Millisecond,
	})
	if p.MaxConcurrentStreams != 500 || p.MaxReadFrameSize != 32<<10 {
		t.Fatalf("override mcs=%d frame=%d", p.MaxConcurrentStreams, p.MaxReadFrameSize)
	}
	if p.UploadFlushBytes != 32<<10 || p.UploadPipeBytes != 64<<10 {
		t.Fatalf("flush=%d pipe=%d", p.UploadFlushBytes, p.UploadPipeBytes)
	}
	if p.DownloadFillWait != 5*time.Millisecond || p.DownloadFillMaxWall != 20*time.Millisecond {
		t.Fatalf("wait=%v wall=%v", p.DownloadFillWait, p.DownloadFillMaxWall)
	}
	if p.StreamRecvWindow != DefaultStreamRecvWindow {
		t.Fatalf("default stream window lost: %d", p.StreamRecvWindow)
	}
}

func TestResolveLabBulkClearsIdlePing(t *testing.T) {
	p := Resolve(LabBulkTuning())
	if p.StreamRecvWindow != LabBulkStreamRecvWindow || p.MaxReadFrameSize != LabBulkMaxReadFrameSize {
		t.Fatalf("bulk windows/frame stream=%d frame=%d", p.StreamRecvWindow, p.MaxReadFrameSize)
	}
	if p.ReadIdleTimeout != 0 || p.PingTimeout != 0 {
		t.Fatalf("lab bulk must disable idle PING, got idle=%v ping=%v", p.ReadIdleTimeout, p.PingTimeout)
	}
}

func TestAutoUploadFlushBytes(t *testing.T) {
	if AutoUploadFlushBytes(16<<10) != 16<<10 {
		t.Fatal("chrome frame should auto-flush at frame size")
	}
	if AutoUploadFlushBytes(1<<20) != DefaultUploadFlushBytes {
		t.Fatal("large frame should keep 256KiB flush")
	}
}

func TestNewTransportAppliesDefaults(t *testing.T) {
	tr, err := NewBulkHTTP2Transport(nil, func(ctx context.Context, network, addr string, cfg *tls.Config) (net.Conn, error) {
		return nil, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if tr.MaxReadFrameSize != DefaultMaxReadFrameSize {
		t.Fatalf("MaxReadFrameSize=%d", tr.MaxReadFrameSize)
	}
	if tr.ReadIdleTimeout != DefaultReadIdleTimeout || tr.PingTimeout != DefaultPingTimeout {
		t.Fatalf("idle=%v ping=%v", tr.ReadIdleTimeout, tr.PingTimeout)
	}
	if tr.MasqueUploadFlushBytes != DefaultUploadFlushBytes {
		t.Fatalf("flush=%d", tr.MasqueUploadFlushBytes)
	}
}

func TestServerConfigResolved(t *testing.T) {
	srv := BulkHTTP2ServerConfigResolved(Resolve(Tuning{}))
	if srv.MaxConcurrentStreams != DefaultMaxConcurrentStreams || srv.MaxReadFrameSize != DefaultMaxReadFrameSize {
		t.Fatalf("mcs=%d frame=%d", srv.MaxConcurrentStreams, srv.MaxReadFrameSize)
	}
	bulk := BulkHTTP2ServerConfigResolved(Resolve(LabBulkTuning()))
	if bulk.MaxConcurrentStreams != LabBulkMaxConcurrentStreams || bulk.MaxReadFrameSize != LabBulkMaxReadFrameSize {
		t.Fatalf("bulk mcs=%d frame=%d", bulk.MaxConcurrentStreams, bulk.MaxReadFrameSize)
	}
}
