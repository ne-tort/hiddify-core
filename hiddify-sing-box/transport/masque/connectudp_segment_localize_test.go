package masque

import (
	"testing"

	"github.com/sagernet/sing-box/transport/masque/connectudp"
)

const segmentRunIDBase = uint32(0x5E6E0000)

// TestLocalizeConnectUDPSegmentUploadMatrixFlood logs per-site upload @ unlimited flood (2s).
func TestLocalizeConnectUDPSegmentUploadMatrixFlood(t *testing.T) {
	payload := connectudpDefaultBenchPayload()
	run := func(id uint32, fn func(testing.TB, uint32, float64, int) SegmentUploadResult) SegmentUploadResult {
		return fn(t, segmentRunIDBase|id, 0, payload)
	}

	l0 := run(1, benchSegmentL0LoopbackUpload)
	logSegmentUpload(t, l0)

	h3direct := run(2, benchSegmentH3ClientDirectUpload)
	logSegmentUpload(t, h3direct)

	h3listen := run(3, benchSegmentH3SessionListenUpload)
	logSegmentUpload(t, h3listen)

	h2dial := run(4, benchSegmentH2DialSessionUpload)
	logSegmentUpload(t, h2dial)

	h2listen := run(5, benchSegmentH2SessionListenUpload)
	logSegmentUpload(t, h2listen)

	h2wp := run(6, benchSegmentH2WritePacketUpload)
	logSegmentUpload(t, h2wp)

	for _, pair := range []struct {
		before, after SegmentUploadResult
	}{
		{l0, h3direct},
		{h3direct, h3listen},
		{h2dial, h2listen},
		{h2listen, h2wp},
	} {
		if ratio, hint := segmentLossAppearsAfter(pair.before, pair.after); hint != "" {
			t.Logf("PINPOINT %s", hint)
			if site := segmentRelayLossSite(pair.after); site != "" {
				t.Logf("PINPOINT relay-loss site=%s ratio=%.2f", site, ratio)
			}
		}
	}
}

// TestLocalizeConnectUDPSegmentUploadMatrixPaced200 logs per-site upload @ paced 200 Mbit/s.
func TestLocalizeConnectUDPSegmentUploadMatrixPaced200(t *testing.T) {
	const paced = 200.0
	payload := connectudpDefaultBenchPayload()
	run := func(id uint32, fn func(testing.TB, uint32, float64, int) SegmentUploadResult) SegmentUploadResult {
		return fn(t, segmentRunIDBase|0x100|id, paced, payload)
	}

	for _, r := range []SegmentUploadResult{
		run(1, benchSegmentL0LoopbackUpload),
		run(2, benchSegmentH3ClientDirectUpload),
		run(3, benchSegmentH3SessionListenUpload),
		run(4, benchSegmentH2DialSessionUpload),
		run(5, benchSegmentH2SessionListenUpload),
	} {
		logSegmentUpload(t, r)
		if r.Stats.LossPct > 0.5 || !r.Stats.BurstZeroLossOK(payload, connectudp.DefaultBurstMinRxRatio) {
			if r.Stats.LossPct > 0.5 {
				t.Logf("PINPOINT paced@200 site=%s loss=%.2f%% (code=%s)", r.Site, r.Stats.LossPct, r.CodeRef)
			}
		}
	}
}

// TestLocalizeConnectUDPSegmentDownloadMatrix logs S2C fountain per pinned client entry (H2/H3).
// Subtests isolate each site (no back-to-back fountain cross-talk).
func TestLocalizeConnectUDPSegmentDownloadMatrix(t *testing.T) {
	payload := connectudpDefaultBenchPayload()
	var h3direct, h3session, h2direct, h2session SegmentDownloadResult

	t.Run("H3-S2C-Direct", func(t *testing.T) {
		h3direct = benchSegmentH3S2CDirectDownload(t, payload)
		logSegmentDownload(t, h3direct)
	})
	t.Run("H3-S2C-Session", func(t *testing.T) {
		h3session = benchSegmentH3S2CSessionDownload(t, payload)
		logSegmentDownload(t, h3session)
	})
	t.Run("H2-S2C-Direct", func(t *testing.T) {
		h2direct = benchSegmentH2S2CDirectDownload(t, payload)
		logSegmentDownload(t, h2direct)
	})
	t.Run("H2-S2C-Session", func(t *testing.T) {
		h2session = benchSegmentH2S2CSessionDownload(t, payload)
		logSegmentDownload(t, h2session)
	})

	if h3direct.Mbps > 0 {
		ratio := h3session.Mbps / h3direct.Mbps
		t.Logf("PINPOINT H3 S2C session/direct ratio=%.2f (code session=%s)", ratio, segmentCodeRef[segmentH3S2CSession])
		if ratio < 0.75 && h3direct.Mbps >= 400 {
			t.Logf("PINPOINT H3 S2C bottleneck: session.ListenPacket wrapper or DatagramSplitConn")
		}
	}
	if h2direct.Mbps > 0 {
		ratio := h2session.Mbps / h2direct.Mbps
		t.Logf("PINPOINT H2 S2C session/direct ratio=%.2f", ratio)
	}
}

// TestLocalizeConnectUDPSegmentPinpointH3UploadFlood attributes unlimited-flood loss to a code site.
func TestLocalizeConnectUDPSegmentPinpointH3UploadFlood(t *testing.T) {
	payload := connectudpDefaultBenchPayload()
	l0 := benchSegmentL0LoopbackUpload(t, segmentRunIDBase|0x20, 0, payload)
	h3 := benchSegmentH3ClientDirectUpload(t, segmentRunIDBase|0x21, 0, payload)
	logSegmentUpload(t, l0)
	logSegmentUpload(t, h3)

	if l0.Stats.LossPct > 1 {
		t.Fatalf("L0 loopback baseline loss=%.2f%% — sink/host broken", l0.Stats.LossPct)
	}
	if h3.Stats.LossPct < 5 {
		t.Logf("PINPOINT: H3 flood zero-loss at direct dial — no queue ceiling this run")
		return
	}
	if site := segmentRelayLossSite(h3); site != "" {
		t.Logf("PINPOINT H3 upload flood loss=%.2f%% primary_site=%s streamQ=%d c2s_in=%d sent=%d",
			h3.Stats.LossPct, site, h3.Drops.StreamDatagramQueue, h3.Relay.C2SDatagramIn, h3.Stats.SentPkts)
	}
	if h3.Relay.C2SDatagramIn > 0 && h3.Relay.C2SDatagramIn == h3.Relay.C2SUDPPayloadOut &&
		uint64(h3.Stats.RxPkts) < h3.Relay.C2SDatagramIn {
		t.Logf("PINPOINT: loss after server relay (onward UDP OK) — check sequenced sink drain or client path back")
	}
}

// TestLocalizeConnectUDPSegmentPinpointH2UploadFlood compares H2 dial vs ListenPacket vs WritePacket.
func TestLocalizeConnectUDPSegmentPinpointH2UploadFlood(t *testing.T) {
	payload := connectudpDefaultBenchPayload()
	dial := benchSegmentH2DialSessionUpload(t, segmentRunIDBase|0x30, 0, payload)
	listen := benchSegmentH2SessionListenUpload(t, segmentRunIDBase|0x31, 0, payload)
	logSegmentUpload(t, dial)
	logSegmentUpload(t, listen)

	if dial.Stats.LossPct > 5 {
		t.Logf("PINPOINT H2 dial loss=%.2f%% unexpected — reference path is sync capsule Write", dial.Stats.LossPct)
	}
	if dial.Mbps > 0 {
		ratio := listen.Mbps / dial.Mbps
		t.Logf("PINPOINT H2 listen/dial ratio=%.2f loss_dial=%.2f%% loss_listen=%.2f%%",
			ratio, dial.Stats.LossPct, listen.Stats.LossPct)
		if ratio < 0.75 && dial.Mbps >= 200 {
			t.Logf("PINPOINT H2 bottleneck: session.ListenPacket / asymmetric_packet_conn.go")
		}
	}
}

// TestLocalizeConnectUDPSegmentH3AsymmetricVsBidi isolates explicit asymmetric legs vs bidi DialH3Production.
func TestLocalizeConnectUDPSegmentH3AsymmetricVsBidi(t *testing.T) {
	payload := connectudpDefaultBenchPayload()
	asymMbps, asymSt, err := benchConnectUDPH3AsymmetricUploadZeroLoss(t, segmentBenchDuration(), payload)
	if err != nil {
		t.Fatalf("asymmetric upload: %v", err)
	}
	bidi := benchSegmentH3BidiDirectUpload(t, segmentRunIDBase|0x41, 0, payload)
	asym := SegmentUploadResult{
		Site:     "H3-asymmetric-DialAddrLeg",
		CodeRef:  "connectudp_dial_h3_asymmetric.go + h2/asymmetric_packet_conn.go",
		Mode:     "flood",
		PayloadB: payload,
		Mbps:     asymMbps,
		Stats:    asymSt,
	}
	logSegmentUpload(t, asym)
	logSegmentUpload(t, bidi)

	if asym.Mbps > 0 && bidi.Mbps > 0 {
		t.Logf("PINPOINT H3 asymmetric/bidi ratio=%.2f loss_asym=%.2f%% loss_bidi=%.2f%%",
			asym.Mbps/bidi.Mbps, asym.Stats.LossPct, bidi.Stats.LossPct)
	}
	if asym.Drops.StreamDatagramQueue > bidi.Drops.StreamDatagramQueue {
		t.Logf("PINPOINT: extra streamQ drops on asymmetric leg (relay/h3_asymmetric.go upload-only)")
	}
}

func connectudpDefaultBenchPayload() int {
	return connectudp.DefaultBenchUDPPayloadLen
}
