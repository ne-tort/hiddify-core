package h3

import (
	"net"
	"testing"
)

func TestDownloadEagerWindowEnabled(t *testing.T) {
	t.Setenv(envDownloadEagerWindow, "")
	if !DownloadEagerWindowEnabled() {
		t.Fatal("default eager window must be on")
	}
	t.Setenv(envDownloadEagerWindow, "0")
	if DownloadEagerWindowEnabled() {
		t.Fatal("MASQUE_QUIC_DOWNLOAD_EAGER_WINDOW=0 must disable")
	}
}

func TestWrapBidiWindowInstantCreditS2COnly(t *testing.T) {
	t.Parallel()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go func() {
		c, _ := ln.Accept()
		if c != nil {
			buf := make([]byte, 64*1024)
			_, _ = c.Write(buf)
			_ = c.Close()
		}
	}()
	cli, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer cli.Close()
	wrapped := WrapBidiWindow(cli, BidiWindowConfig{
		RTT:              DefaultBidiWindowRTT,
		WindowBytes:      DefaultBidiWindowSizeBytes,
		InstantCreditS2C: true,
	})
	w := wrapped.(*windowedBidiConn)
	if !w.instantCreditS2C {
		t.Fatal("InstantCreditS2C not set")
	}
	if w.instantCredit {
		t.Fatal("InstantCreditS2C must not enable full instantCredit")
	}
	if w.s2cCreditDelay() != 0 {
		t.Fatal("S2C credit delay must be 0 with InstantCreditS2C")
	}
	if w.creditDelay() != DefaultBidiWindowRTT {
		t.Fatal("C2S credit delay must keep RTT with InstantCreditS2C only")
	}
}
