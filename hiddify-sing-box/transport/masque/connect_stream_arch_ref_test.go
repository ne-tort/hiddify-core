//go:build masque_arch_ledger

package masque

import (
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sagernet/sing-box/transport/masque/h3"
	strm "github.com/sagernet/sing-box/transport/masque/stream"
)

// TestArchREF2H2OParityAudit (REF2-1): frozen h2o connect.conf vs RelayTCPTunnel constants.
func TestArchREF2H2OParityAudit(t *testing.T) {
	if len(ArchH2OParityAudit) < 5 {
		t.Fatalf("ArchH2OParityAudit: %d rows want >= 5", len(ArchH2OParityAudit))
	}
	for _, row := range ArchH2OParityAudit {
		if !row.Parity {
			t.Logf("REF2-1 documented gap %s: h2o=%s sb=%s (%s)", row.Attr, row.H2OValue, row.SBValue, row.KPINote)
			continue
		}
	}
	const relayBufLen = 256 * 1024
	if got := ArchH2OParityRelayBufLen(); got != relayBufLen {
		t.Fatalf("RelayTunnelBufLen=%d want %d", got, relayBufLen)
	}
	if got := ArchH2OParityRelayFlushBytes(); got != relayBufLen {
		t.Fatalf("RelayTunnelFlushBytes=%d want %d", got, relayBufLen)
	}
	if ArchH2OParityRelayBufLen() != strm.RelayTunnelBufLen {
		t.Fatal("audit buf len drift from stream package")
	}

	root := singboxRootForArchRef2(t)
	confPath := filepath.Join(root, "testdata", "h2o-connect.conf")
	data, err := os.ReadFile(confPath)
	if err != nil {
		t.Fatalf("read h2o config: %v", err)
	}
	body := string(data)
	for _, needle := range []string{"proxy.tunnel: ON", "proxy.max-buffer-size: 65536"} {
		if !strings.Contains(body, needle) {
			t.Fatalf("h2o connect.conf missing %q", needle)
		}
	}
	t.Logf("REF2-1 audit: %d parity rows; h2o config anchors OK", len(ArchH2OParityAudit))
}

// TestArchServerH2OParityRelayL3 (REF2-4): h2o-parity server relay exceeds VPS KPI on instant link;
// sb-windowed peer stays in FC band — proves relay is not the 15 Mbit/s root cause.
func TestArchServerH2OParityRelayL3(t *testing.T) {
	t.Setenv("MASQUE_RELAY_TCP_STREAM_HIJACK", "1")

	const duration = localizeBenchDuration

	instant := benchRelayH3Download(t, instantBidiLink{}, duration)
	if instant.err != nil {
		t.Fatalf("h2o-parity instant: %v", instant.err)
	}
	t.Logf("REF2-4 h2o-parity relay instant: %.1f Mbit/s", instant.mbps)
	if instant.mbps <= connectStreamVPSKPITargetDownMbps {
		t.Fatalf("h2o-parity instant %.1f Mbit/s (want > %.0f K-SRV KPI)", instant.mbps, connectStreamVPSKPITargetDownMbps)
	}

	windowed := benchRelayH3Download(t, benchWindowedBidiLink(), duration)
	if windowed.err != nil {
		t.Fatalf("sb-peer windowed: %v", windowed.err)
	}
	t.Logf("REF2-4 sb-peer windowed: %.1f Mbit/s", windowed.mbps)
	assertConnectStreamWindowedCeilingBand(t, windowed.mbps, "REF2-4 sb-peer windowed relay")

	h2Windowed := benchRelayH2FlushDownload(t, benchWindowedBidiLink(), duration)
	if h2Windowed.err != nil {
		t.Fatalf("H2 flush windowed: %v", h2Windowed.err)
	}
	t.Logf("REF2-4 H2 flush windowed: %.1f Mbit/s", h2Windowed.mbps)
	if windowed.mbps <= connectStreamVPSKPITargetDownMbps {
		t.Fatalf("h2o-parity H3 windowed %.1f Mbit/s (want > %.0f K-SRV KPI)", windowed.mbps, connectStreamVPSKPITargetDownMbps)
	}
	if h2Windowed.mbps <= connectStreamVPSKPITargetDownMbps {
		t.Fatalf("H2 flush windowed %.1f Mbit/s (want > %.0f K-SRV KPI)", h2Windowed.mbps, connectStreamVPSKPITargetDownMbps)
	}
	t.Log("REF2-4 verdict: server relay h2o-parity >21 on instant + windowed (eager WINDOW default)")
}

// TestArchPeerSwapL3WriteTo (REF4-1): same L3 WriteTo harness, sb-peer vs h2o-peer mock.
// Post-ADR: eager WINDOW lifts sb-peer to KPI; Mbps delta is informational — wire differential is REF2-2.
func TestArchPeerSwapL3WriteTo(t *testing.T) {
	const duration = localizeBenchDuration

	sbMbps, sbBytes, err := benchBypassRowDownloadMbps(benchWindowedBidiLink(), duration)
	if err != nil {
		t.Fatalf("sb peer: %v", err)
	}
	h2oMbps, h2oBytes, err := benchBypassRowDownloadMbps(bypassB2BidiLink(), duration)
	if err != nil {
		t.Fatalf("h2o peer (B2 no S2C window): %v", err)
	}
	t.Logf("REF4-1 peer swap: sb=%.1f (%d B) h2o=%.1f (%d B)", sbMbps, sbBytes, h2oMbps, h2oBytes)

	assertConnectStreamWindowedCeilingBand(t, sbMbps, "REF4-1 sb peer")
	assertConnectStreamWindowedCeilingBand(t, h2oMbps, "REF4-1 h2o peer")
	if sbMbps <= 0 || h2oMbps <= 0 {
		t.Fatalf("REF4-1 peer swap invalid throughput: sb=%.1f h2o=%.1f", sbMbps, h2oMbps)
	}
	t.Log("REF4-1 verdict: both peers KPI pass post-ADR; S2C credit differential → TestArchREF2WireWindowUpdateTrace")
}

// TestArchREF2EndpointRelayPathAudit (REF2-5): frozen audit table for template/authority/endpoint relay parity.
func TestArchREF2EndpointRelayPathAudit(t *testing.T) {
	if len(ArchEndpointRelayAudit) < 2 {
		t.Fatalf("ArchEndpointRelayAudit: %d rows want >= 2", len(ArchEndpointRelayAudit))
	}
	for _, row := range ArchEndpointRelayAudit {
		if !row.Parity {
			t.Fatalf("REF2-5 gap %s: relay=%s delegate=%s", row.Path, row.RelayFn, row.Delegate)
		}
	}
	t.Logf("REF2-5 audit: %d relay path rows; template/endpoint share RelayTCPTunnel", len(ArchEndpointRelayAudit))
}

// TestArchREF2UploadDownloadInterleave (REF2-3): h2o-parity H3 relay duplex does not regress
// download-only throughput on windowed sb peer (goroutine split + io.CopyBuffer interleave OK).
func TestArchREF2UploadDownloadInterleave(t *testing.T) {
	const duration = localizeBenchDuration

	dlOnly := benchRelayH3Download(t, benchWindowedBidiLink(), duration)
	duplex := runConnectStreamDuplexWriteToBench(t, benchWindowedBidiLink(), connectStreamLocalizeDownloadKPIMin/2)
	if dlOnly.err != nil {
		t.Fatalf("download-only relay: %v", dlOnly.err)
	}
	t.Logf("REF2-3 relay download-only=%.1f full-client duplex=%.1f Mbit/s", dlOnly.mbps, duplex.mbps)
	assertConnectStreamWindowedCeilingBand(t, dlOnly.mbps, "REF2-3 relay download-only")
	assertConnectStreamWindowedCeilingBand(t, duplex.mbps, "REF2-3 client duplex")
	if duplex.mbps > dlOnly.mbps+2 {
		t.Fatalf("duplex %.1f unexpectedly above relay-only %.1f — interleave regression", duplex.mbps, dlOnly.mbps)
	}
}

// benchS2CCreditGrantsDuringDownload counts S2C credit releases on a windowed bidi link during WriteTo drain.
func benchS2CCreditGrantsDuringDownload(link windowedBidiLink, duration time.Duration) (int64, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
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
		return 0, err
	}
	client := link.wrap(cli)
	wt, ok := client.(io.WriterTo)
	if !ok {
		close(stop)
		_ = cli.Close()
		_ = ln.Close()
		return 0, fmt.Errorf("windowed bidi conn lacks io.WriterTo")
	}
	sink := &benchWriteToSink{deadline: time.Now().Add(duration)}
	_, _ = wt.WriteTo(sink)
	grants := h3.BidiWindowS2CCreditGrants(client)
	close(stop)
	_ = cli.Close()
	_ = ln.Close()
	return grants, nil
}

// TestArchREF2WireWindowUpdateTrace (REF2-2): sb-peer windowed S2C emits credit grants per 64 KiB/RTT;
// h2o-peer (noLimitS2C) does not — models WINDOW_UPDATE differential on download leg.
func TestArchREF2WireWindowUpdateTrace(t *testing.T) {
	const duration = localizeBenchDuration

	sbGrants, err := benchS2CCreditGrantsDuringDownload(benchWindowedBidiLink(), duration)
	if err != nil {
		t.Fatalf("sb-peer trace: %v", err)
	}
	h2oGrants, err := benchS2CCreditGrantsDuringDownload(bypassB2BidiLink(), duration)
	if err != nil {
		t.Fatalf("h2o-peer trace: %v", err)
	}
	t.Logf("REF2-2 S2C credit grants: sb-peer=%d h2o-peer=%d (window=%d rtt=%s)",
		sbGrants, h2oGrants, localizeBenchWindowBytes, localizeBenchRTT)

	if sbGrants < 5 {
		t.Fatalf("sb-peer grants %d want >=5 (64 KiB/RTT WINDOW_UPDATE cycles)", sbGrants)
	}
	if h2oGrants != 0 {
		t.Fatalf("h2o-peer grants %d want 0 (unlimited S2C / no WINDOW_UPDATE stall)", h2oGrants)
	}
	if sbGrants <= h2oGrants {
		t.Fatalf("peer differential too small: sb=%d h2o=%d", sbGrants, h2oGrants)
	}
	t.Log("REF2-2 verdict: sb-peer S2C window throttles download; h2o-peer bypass confirms peer FC root cause")
}

// TestArchREF1InProcReproGate (REF1-1 local): reproduces peer differential without Docker —
// post-ADR sb-peer passes KPI (eager WINDOW); S2C credit grant differential is REF2-2.
func TestArchREF1InProcReproGate(t *testing.T) {
	const duration = localizeBenchDuration

	sbMbps, _, err := benchBypassRowDownloadMbps(benchWindowedBidiLink(), duration)
	if err != nil {
		t.Fatalf("sb peer: %v", err)
	}
	h2oMbps, _, err := benchBypassRowDownloadMbps(bypassB2BidiLink(), duration)
	if err != nil {
		t.Fatalf("h2o peer: %v", err)
	}
	t.Logf("REF1-1 in-proc repro: sb-peer=%.1f h2o-peer=%.1f Mbit/s", sbMbps, h2oMbps)

	assertConnectStreamWindowedCeilingBand(t, sbMbps, "REF1-1 sb-peer (h3-core analog)")
	assertConnectStreamWindowedCeilingBand(t, h2oMbps, "REF1-1 h2o-peer (h3-authority-h2o analog)")
	t.Log("REF1-1 verdict: post-ADR both peers KPI pass; wire FC differential → TestArchREF2WireWindowUpdateTrace")
}

func singboxRootForArchRef2(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	dir := wd
	for i := 0; i < 10; i++ {
		if _, err := os.Stat(filepath.Join(dir, "testdata", "h2o-connect.conf")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	t.Fatal("could not find transport/masque/testdata from", wd)
	return ""
}
