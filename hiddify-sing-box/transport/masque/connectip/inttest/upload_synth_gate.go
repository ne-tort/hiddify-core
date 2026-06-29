package inttest

// Native H3 upload synth/localize gate runners (W-IP-9 IP-9-PR0).

import (
	"context"
	"net"
	"runtime"
	"sync/atomic"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/sagernet/sing-box/transport/masque"
	M "github.com/sagernet/sing/common/metadata"
)

// RunGATEConnectIPUploadSynthNative completes the upload synth gate with native H3 C2S.
func RunGATEConnectIPUploadSynthNative(t *testing.T) {
	t.Helper()
	duration := masque.LocalizeBenchDuration

	nativeMbps, _ := BenchConnectIPNativeUploadH3(t, masque.ConnectIPNativeSynthBenchDur)

	runtime.GC()
	time.Sleep(200 * time.Millisecond)

	pipe := masque.BenchConnectIPUploadInstantL1(t, duration)
	if pipe.Err != nil {
		t.Fatalf("pipe L1: %v", pipe.Err)
	}
	t.Logf("pipe L1 upload (no QUIC): %.1f Mbit/s (after native)", pipe.Mbps)

	ratio := 0.0
	if pipe.Mbps > 0 {
		ratio = nativeMbps / pipe.Mbps
	}
	t.Logf("native H3 upload: %.1f Mbit/s; native/pipe=%.2f (min %.2f)",
		nativeMbps, ratio, masque.ConnectIPSynthPipeMinRatio)
	t.Logf("localization: %s", masque.ConnectIPUploadNativeHint(pipe.Mbps, nativeMbps))

	if nativeMbps < masque.ConnectIPSynthRegressionFloorUpMbps {
		t.Fatalf("native upload regression: %.1f < %.1f Mbit/s",
			nativeMbps, masque.ConnectIPSynthRegressionFloorUpMbps)
	}
	if ratio < masque.ConnectIPSynthPipeMinRatio {
		t.Fatalf("native/pipe ratio %.2f < %.2f — QUIC/datagram C2S is dominant bottleneck (Docker would not help)",
			ratio, masque.ConnectIPSynthPipeMinRatio)
	}
	if pipe.Mbps >= masque.ConnectIPSynthPipeFastMinMbps {
		t.Logf("fast-pipe native/pipe=%.2f (floor %.2f target %.2f @ pipe>=%.0f)",
			ratio, masque.ConnectIPSynthPipeFastFloorRatio,
			masque.ConnectIPSynthPipeFastTargetRatio, masque.ConnectIPSynthPipeFastMinMbps)
		if ratio < masque.ConnectIPSynthPipeFastFloorRatio {
			t.Fatalf("native/pipe %.2f < fast-pipe floor %.2f (pipe L1 %.1f) — QUIC/datagram egress gap",
				ratio, masque.ConnectIPSynthPipeFastFloorRatio, pipe.Mbps)
		}
		if ratio < masque.ConnectIPSynthPipeFastTargetRatio {
			t.Logf("OPEN: native/pipe %.2f < target %.2f — Docker connect-ip-h3-tun after synth close",
				ratio, masque.ConnectIPSynthPipeFastTargetRatio)
		}
	}
	if nativeMbps < masque.ConnectIPSynthProdMinMbps {
		t.Logf("OPEN: native upload %.1f < DoD %.0f — synth gate PASS; Docker connect-ip-h3-tun @0ms is next KPI",
			nativeMbps, masque.ConnectIPSynthProdMinMbps)
	}
}

// RunLocalizeConnectIPUploadNativeObs logs drop counters and native/pipe ratio (localization only).
func RunLocalizeConnectIPUploadNativeObs(t *testing.T) {
	t.Helper()
	duration := masque.LocalizeBenchDuration

	streamDropBefore := http3.StreamDatagramQueueDropTotal()
	rcvDropBefore := quic.DatagramReceiveQueueDropTotal()

	nativeMbps, _ := BenchConnectIPNativeUploadH3(t, masque.ConnectIPNativeSynthBenchDur)

	runtime.GC()
	time.Sleep(200 * time.Millisecond)

	pipe := masque.BenchConnectIPUploadInstantL1(t, duration)
	if pipe.Err != nil {
		t.Fatalf("pipe L1: %v", pipe.Err)
	}

	streamDrop := http3.StreamDatagramQueueDropTotal() - streamDropBefore
	rcvDrop := quic.DatagramReceiveQueueDropTotal() - rcvDropBefore
	ratio := nativeMbps / pipe.Mbps

	t.Logf("localize upload obs: pipe=%.1f native=%.1f ratio=%.2f stream_drops=%d rcv_drops=%d",
		pipe.Mbps, nativeMbps, ratio, streamDrop, rcvDrop)
	t.Logf("hint: %s", masque.ConnectIPUploadNativeHint(pipe.Mbps, nativeMbps))

	if streamDrop > 0 || rcvDrop > 0 {
		t.Fatalf("datagram drops during upload: stream=%d rcv=%d — fix ingress/queue before Docker",
			streamDrop, rcvDrop)
	}
}

// RunLocalizeConnectIPUploadDatagramWakeCoalescing guards coalesced QUIC send wake on upload.
func RunLocalizeConnectIPUploadDatagramWakeCoalescing(t *testing.T) {
	t.Helper()
	var wakeCount atomic.Int64
	restore := quic.SetMasqueWakeConnSendHook(func() { wakeCount.Add(1) })
	defer restore()

	uploadLn := masque.StartConnectIPNativeUploadSink(t)
	proxyPort := StartNativeConnectIPH3Server(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	session, err := (masque.CoreClientFactory{}).NewSession(ctx, NativeH3ClientOptions(proxyPort))
	if err != nil {
		t.Fatalf("session: %v", err)
	}
	defer session.Close()
	if _, err := session.OpenIPSession(ctx); err != nil {
		t.Fatalf("OpenIPSession: %v", err)
	}

	upPort := uint16(uploadLn.Addr().(*net.TCPAddr).Port)
	upConn, err := session.DialContext(ctx, "tcp", M.ParseSocksaddrHostPort("127.0.0.1", upPort))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer upConn.Close()

	wakeCount.Store(0)
	upBytes, nativeMbps, upErr := masque.MeasureNativeUploadMbps(upConn, 1500*time.Millisecond)
	if upErr != nil && upBytes == 0 {
		t.Fatalf("upload: %v", upErr)
	}
	wakes := wakeCount.Load()
	estDatagrams := upBytes / int64(masque.ConnectIPSynthWakeEstSegmentBytes)
	if estDatagrams < 1 {
		estDatagrams = 1
	}
	wakePerDatagram := float64(wakes) / float64(estDatagrams)
	t.Logf("wake coalesce obs: native=%.1f Mbit/s bytes=%d wakes=%d est_dgrams=%d (seg~%dB) wake/est_dgram=%.3f",
		nativeMbps, upBytes, wakes, estDatagrams, masque.ConnectIPSynthWakeEstSegmentBytes, wakePerDatagram)

	if nativeMbps < masque.ConnectIPSynthRegressionFloorUpMbps {
		t.Fatalf("native upload regression: %.1f < %.1f Mbit/s", nativeMbps, masque.ConnectIPSynthRegressionFloorUpMbps)
	}
	if wakePerDatagram > 1.5 {
		t.Fatalf("wake storm: wake/est_dgram=%.3f > 1.5 — egress/ingress wake not coalesced", wakePerDatagram)
	}
}
