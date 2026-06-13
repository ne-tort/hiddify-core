package h3

import (
	"sync/atomic"
	"testing"
)

func TestBidiUploadWakeDuringDownloadEnv(t *testing.T) {
	cases := []struct {
		env  string
		want bool
	}{
		{"", true},
		{"1", true},
		{"0", false},
		{"off", true},
	}
	for _, tc := range cases {
		t.Run(tc.env, func(t *testing.T) {
			t.Setenv(envH3BidiUploadWake, tc.env)
			if got := BidiUploadWakeDuringDownload(); got != tc.want {
				t.Fatalf("BidiUploadWakeDuringDownload() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestTunnelConnWakeBidiSendAfterUploadGating(t *testing.T) {
	t.Setenv(envH3BidiUploadWake, "1")
	sink := &bidiWakeRecorder{}
	c := NewTunnelConn(TunnelConnParams{
		H3Stream:     &testH3ConnectStream{},
		BidiWakeSink: sink,
	})

	c.wakeBidiSendAfterUpload()
	if sink.upload.Load() != 0 {
		t.Fatalf("expected no wake without downloadActive, got %d", sink.upload.Load())
	}

	atomic.StoreInt32(&c.downloadActive, 1)
	c.wakeBidiSendAfterUpload()
	if sink.upload.Load() != 1 {
		t.Fatalf("expected wake with downloadActive, got %d", sink.upload.Load())
	}

	t.Setenv(envH3BidiUploadWake, "0")
	c.wakeBidiSendAfterUpload()
	if sink.upload.Load() != 1 {
		t.Fatalf("expected wake disabled by env, got %d", sink.upload.Load())
	}
}

func TestBidiDownloadDeliveryWakeDuringWriteToEnv(t *testing.T) {
	cases := []struct {
		env  string
		want bool
	}{
		{"", true},
		{"1", true},
		{"0", false},
	}
	for _, tc := range cases {
		t.Run(tc.env, func(t *testing.T) {
			t.Setenv(envH3BidiDownloadWake, tc.env)
			if got := BidiDownloadDeliveryWakeDuringWriteTo(); got != tc.want {
				t.Fatalf("BidiDownloadDeliveryWakeDuringWriteTo() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestTunnelConnWakeBidiSendAfterDownloadDeliveryGating(t *testing.T) {
	t.Setenv(envH3BidiDownloadWake, "1")
	t.Setenv(envH3BidiUploadWake, "0")
	sink := &bidiWakeRecorder{}
	c := NewTunnelConn(TunnelConnParams{
		H3Stream:     &testH3ConnectStream{},
		BidiWakeSink: sink,
	})

	c.wakeBidiSendAfterDownloadDelivery()
	if sink.download.Load() != 0 {
		t.Fatalf("expected no wake without downloadActive, got %d", sink.download.Load())
	}

	atomic.StoreInt32(&c.downloadActive, 1)
	c.wakeBidiSendAfterDownloadDelivery()
	if sink.download.Load() != 1 {
		t.Fatalf("expected wake with downloadActive, got %d", sink.download.Load())
	}

	t.Setenv(envH3BidiDownloadWake, "0")
	c.wakeBidiSendAfterDownloadDelivery()
	if sink.download.Load() != 1 {
		t.Fatalf("expected download wake disabled by env, got %d", sink.download.Load())
	}
}
