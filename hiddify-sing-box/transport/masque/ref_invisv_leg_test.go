package masque

import (
	"net"
	"net/http"
	"testing"
)

const refSynthInstantLinkCeilingMbps = 2000.0 // mock / pipe / h2o relay (no QUIC dataplane)
const refSynthH3QUICInstantCeilingMbps = 2000.0 // full H3 CONNECT-stream in-proc (QUIC+HTTP/3; coalesced DATA frames)
const refSynthInProcStackFloorMbps = 200.0 // full QUIC CONNECT-stream in-proc (below relay-only ceiling)

// TestREFInvisvClientLegDownload — Invisv-shaped thin client + instant link download ceiling.
func TestREFInvisvClientLegDownload(t *testing.T) {
	h := startConnectStreamDownloadHarness(t, instantBidiLink{})
	defer h.close()
	n, mbps, err := measureTCPDownloadWriteToMbps(h.conn, connectStreamSynthProdBenchDuration)
	if err != nil && n == 0 {
		t.Fatalf("REF-Invisv-client download: %v", err)
	}
	t.Logf("REF-Invisv-client download: %.1f Mbit/s (%d bytes)", mbps, n)
	if mbps < refSynthInProcStackFloorMbps {
		t.Fatalf("REF-Invisv-client: %.1f Mbit/s (want >= %.0f in-proc stack)", mbps, refSynthInProcStackFloorMbps)
	}
}

// TestREFInvisvClientLegUpload — Invisv-shaped thin client upload on instant link.
func TestREFInvisvClientLegUpload(t *testing.T) {
	h := startConnectStreamUploadHarness(t, instantBidiLink{})
	defer h.close()
	n, mbps, err := measureTCPUploadMbps(h.conn, connectStreamSynthProdBenchDuration)
	if err != nil && n == 0 {
		t.Fatalf("REF-Invisv-client upload: %v", err)
	}
	t.Logf("REF-Invisv-client upload: %.1f Mbit/s (%d bytes)", mbps, n)
	if mbps < refSynthInProcStackFloorMbps {
		t.Fatalf("REF-Invisv-client upload: %.1f Mbit/s (want >= %.0f)", mbps, refSynthInProcStackFloorMbps)
	}
}

// TestREFH2oServerLegDownload — h2o proxy.tunnel plain relay (no batched duplex wake) on instant link.
func TestREFH2oServerLegDownload(t *testing.T) {
	t.Setenv("MASQUE_RELAY_TCP_BATCHED_DUPLEX_WAKE", "0")
	t.Setenv("MASQUE_RELAY_TCP_SKIP_PRIME", "1")
	t.Setenv("MASQUE_RELAY_TCP_STREAM_HIJACK", "1")

	setup := func(t *testing.T) (net.Conn, http.ResponseWriter, func()) {
		return startRelayDownloadTarget(t), &mockH3RelayResponse{}, func() {}
	}
	n, mbps := benchRelayTCPTunnelDownload(t, relayInstantLink{}, setup)
	t.Logf("REF-h2o-server download: %.1f Mbit/s (%d bytes)", mbps, n)
	if mbps < refSynthInstantLinkCeilingMbps {
		t.Fatalf("REF-h2o-server: %.1f Mbit/s (want >= %.0f)", mbps, refSynthInstantLinkCeilingMbps)
	}
}

// TestREFMinimalBidiLeg — net.Pipe + io.CopyBuffer both halves (L1 upper bound).
func TestREFMinimalBidiLeg(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	payload := make([]byte, 256*1024)
	go func() {
		defer server.Close()
		for i := 0; i < 512; i++ {
			if _, err := server.Write(payload); err != nil {
				return
			}
		}
	}()

	n, mbps, err := measureTCPDownloadWriteToMbps(benchConnWriteTo{client}, connectStreamSynthProdBenchDuration)
	if err != nil && n == 0 {
		t.Fatalf("REF-minimal-bidi: %v", err)
	}
	t.Logf("REF-minimal-bidi download: %.1f Mbit/s (%d bytes)", mbps, n)
	if mbps < refSynthInstantLinkCeilingMbps {
		t.Fatalf("REF-minimal-bidi: %.1f Mbit/s (want >= %.0f L1 ceiling)", mbps, refSynthInstantLinkCeilingMbps)
	}
}

// TestREFMasqueradeShapeLegDuplex — symmetric channel relay mock (architectural ceiling, no wake).
func TestREFMasqueradeShapeLegDuplex(t *testing.T) {
	down, up, minLeg := benchMasqueradeDuplexMinMbps(connectStreamSynthProdBenchDuration)
	t.Logf("REF-masquerade-shape duplex: down=%.1f up=%.1f min=%.1f", down, up, minLeg)
	if minLeg < refSynthInstantLinkCeilingMbps {
		t.Fatalf("REF-masquerade-shape duplex min: %.1f (want >= %.0f)", minLeg, refSynthInstantLinkCeilingMbps)
	}
}
