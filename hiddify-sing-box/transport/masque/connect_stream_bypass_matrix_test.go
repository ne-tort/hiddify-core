package masque

import (
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"github.com/sagernet/sing-box/transport/masque/h3"
)

func startWindowedBypassFeeder(t *testing.T, link windowedBidiLink, duration time.Duration) (net.Conn, func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	buf := make([]byte, 256*1024)
	done := make(chan struct{})
	go func() {
		for {
			srv, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				deadline := time.Now().Add(duration + 500*time.Millisecond)
				for time.Now().Before(deadline) {
					select {
					case <-done:
						return
					default:
					}
					if _, err := c.Write(buf); err != nil {
						return
					}
				}
			}(srv)
		}
	}()
	cli, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		close(done)
		_ = ln.Close()
		t.Fatalf("dial: %v", err)
	}
	return link.wrap(cli), func() {
		close(done)
		_ = cli.Close()
		_ = ln.Close()
	}
}

// benchBypassRowDownloadMbps measures WriteTo download through a windowed bidi link (download-only wire model).
func benchBypassRowDownloadMbps(link windowedBidiLink, duration time.Duration) (float64, int64, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, 0, err
	}
	buf := make([]byte, 256*1024)
	stop := make(chan struct{})
	go func() {
		for {
			srv, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				deadline := time.Now().Add(duration + 500*time.Millisecond)
				for time.Now().Before(deadline) {
					select {
					case <-stop:
						return
					default:
					}
					if _, err := c.Write(buf); err != nil {
						return
					}
				}
			}(srv)
		}
	}()
	cli, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		close(stop)
		_ = ln.Close()
		return 0, 0, err
	}
	defer cli.Close()
	defer close(stop)
	defer ln.Close()

	client := link.wrap(cli)
	wt, ok := client.(io.WriterTo)
	if !ok {
		close(stop)
		_ = cli.Close()
		_ = ln.Close()
		return 0, 0, fmt.Errorf("windowed bidi conn lacks io.WriterTo")
	}
	sink := &benchWriteToSink{deadline: time.Now().Add(duration)}
	n, err := wt.WriteTo(sink)
	if n == 0 && err != nil {
		return 0, 0, err
	}
	secs := duration.Seconds()
	if secs <= 0 {
		secs = 1
	}
	return float64(n*8) / secs / 1e6, n, nil
}

// TestMasqueConnectStreamBypassMatrix bisects field ceiling via windowed bidi bypass rows B2/B7/B8 (S2).
func TestMasqueConnectStreamBypassMatrix(t *testing.T) {
	const duration = localizeBenchDuration

	type row struct {
		name      string
		link      windowedBidiLink
		wantFast  bool
		wantField bool
	}

	rows := []row{
		{
			name:      "B8_ack_rtt_field_model",
			link:      bypassB8BidiLink(),
			wantField: true,
		},
		{
			name:     "B2_no_src_window",
			link:     bypassB2BidiLink(),
			wantFast: true,
		},
		{
			name:     "B7_instant_ack_unlock",
			link:     bypassB7BidiLink(),
			wantFast: true,
		},
	}

	var b8Mbps float64
	for _, r := range rows {
		r := r
		t.Run(r.name, func(t *testing.T) {
			mbps, n, err := benchBypassRowDownloadMbps(r.link, duration)
			if err != nil {
				t.Fatalf("%s: %v", r.name, err)
			}
			t.Logf("%s: %.1f Mbit/s (%d bytes)", r.name, mbps, n)
			switch {
			case r.wantField:
				b8Mbps = mbps
				min, max := connectStreamCeilingBand()
				if mbps < min || mbps > max {
					t.Fatalf("B8 field model %.1f Mbit/s outside band %.1f–%.1f", mbps, min, max)
				}
			case r.wantFast:
				if mbps < connectStreamVPSKPITargetDownMbps {
					t.Fatalf("%s bypass expected > %.0f Mbit/s, got %.1f", r.name, connectStreamVPSKPITargetDownMbps, mbps)
				}
				if b8Mbps > 0 && mbps < b8Mbps*2 {
					t.Fatalf("%s bypass uplift too small: %.1f vs B8 %.1f", r.name, mbps, b8Mbps)
				}
			}
		})
	}

	t.Logf("bypass matrix verdict: B8 field anchor; B2/B7 unlock wire credit (response window / instant ACK)")
}

// TestMasqueConnectStreamDuplexWriteToDownload (K-S2): prod duplex WriteTo exceeds VPS KPI when
// eager WINDOW_UPDATE is on; legacy ceiling band when off.
func TestMasqueConnectStreamDuplexWriteToDownload(t *testing.T) {
	link := benchWindowedBidiLink()
	if h3.DownloadEagerWindowEnabled() {
		dl := runConnectStreamDuplexWriteToBench(t, link, connectStreamVPSKPITargetDownMbps)
		if dl.mbps <= connectStreamVPSKPITargetDownMbps {
			t.Fatalf("K-S2 prod eager window: %.1f Mbit/s want > %.0f", dl.mbps, connectStreamVPSKPITargetDownMbps)
		}
		return
	}
	dl := runConnectStreamDuplexWriteToBench(t, link, connectStreamLocalizeCeilingMin)
	assertConnectStreamWindowedCeilingBand(t, dl.mbps, "duplex WriteTo download (S5b)")
}

// TestWindowedBidiBridgeDownloadBand checks S2C window + credit in isolation via WriteTo (S5c).
func TestWindowedBidiBridgeDownloadBand(t *testing.T) {
	const duration = localizeBenchDuration
	client, cleanup := startWindowedBypassFeeder(t, benchWindowedBidiLink(), duration)
	defer cleanup()

	sink := &benchWriteToSink{deadline: time.Now().Add(duration)}
	wt, ok := client.(io.WriterTo)
	if !ok {
		t.Fatal("windowed bidi conn must implement io.WriterTo")
	}
	n, err := wt.WriteTo(sink)
	if n == 0 && err != nil {
		t.Fatalf("WriteTo: %v", err)
	}
	if n < localizeBenchMinBytes {
		t.Fatalf("WriteTo bytes=%d want >= %d", n, localizeBenchMinBytes)
	}
	mbps := float64(n*8) / duration.Seconds() / 1e6
	t.Logf("windowed bidi bridge WriteTo: %.1f Mbit/s (%d bytes)", mbps, n)
	if mbps < connectStreamLocalizeCeilingMin || mbps > connectStreamLocalizeCeilingMax {
		t.Fatalf("bridge download %.1f Mbit/s want %.0f–%.0f", mbps, connectStreamLocalizeCeilingMin, connectStreamLocalizeCeilingMax)
	}
}
