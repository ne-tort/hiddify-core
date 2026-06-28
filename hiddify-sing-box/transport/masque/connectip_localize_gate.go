package masque

// In-proc CONNECT-IP TUN order / Docker KPI guard gates (W-IP-TUN IP-TUN-PR1).

import (
	"testing"
	"time"
)

func gateConnectIPTunPostUploadDownload(t *testing.T) {
	t.Helper()
	const benchDur = 400 * time.Millisecond
	h := startConnectIPDownloadHarness(t, instantPacketLink{})
	defer h.close()

	upConn := h.dialRemote(t)
	upBytes, upMbps, err := measureTCPUploadMbps(upConn, benchDur)
	if err != nil {
		t.Fatalf("upload: %v", err)
	}
	if err := upConn.Close(); err != nil {
		t.Fatalf("close upload: %v", err)
	}
	flushConnectIPEgressAfterClose(h)

	downConn := h.dialRemote(t)
	defer downConn.Close()
	downBytes, downMbps, err := measureTCPDownloadMbps(downConn, benchDur)
	if err != nil {
		t.Fatalf("download after upload: %v", err)
	}
	t.Logf("connect-ip tun order upload→download (pipe): up=%.1f (%d B) down=%.1f (%d B)",
		upMbps, upBytes, downMbps, downBytes)
	if downBytes < 32*1024 {
		t.Fatalf("download after upload=%d bytes want >= 32KiB (Docker tun order analog)", downBytes)
	}
}

func gateConnectIPDockerTUNKPIInProcGuard(t *testing.T) {
	t.Helper()
	const dur = localizeBenchDuration
	l1 := benchConnectIPUploadLayerBest(t, "L1-prod", prodInstantPacketLink{}, dur, 3)
	if l1.err != nil {
		t.Fatalf("L1-prod upload: %v", l1.err)
	}
	t.Logf("docker KPI in-proc guard L1-prod upload: %.1f Mbit/s (%d bytes)", l1.mbps, l1.bytes)
	// In-proc instant pipe is the anti-regression anchor; full 80 Mbit/s is Docker @0ms target.
	const inProcL1FloorMbps = 1.0
	if l1.mbps < inProcL1FloorMbps {
		t.Fatalf("L1-prod upload dead: %.1f Mbit/s want >= %.1f before Docker connect-ip-h3-tun", l1.mbps, inProcL1FloorMbps)
	}
	if l1.mbps < connectIPLocalizeFastMbps {
		t.Logf("L1-prod %.1f Mbit/s below Docker up floor %.0f (expected in-proc; run Docker for KPI)", l1.mbps, connectIPLocalizeFastMbps)
	}
}
