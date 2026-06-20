package masque_test

import (
	"runtime"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/sagernet/sing-box/transport/masque"
)

// TestLocalizeConnectIPUploadNativeObs logs drop counters and native/pipe ratio (localization only).
func TestLocalizeConnectIPUploadNativeObs(t *testing.T) {
	duration := masque.ExportLocalizeBenchDuration

	streamDropBefore := http3.StreamDatagramQueueDropTotal()
	rcvDropBefore := quic.DatagramReceiveQueueDropTotal()

	nativeMbps, _ := benchConnectIPNativeUploadH3(t, connectIPNativeSynthBenchDur)

	runtime.GC()
	time.Sleep(200 * time.Millisecond)

	pipe := masque.ExportBenchConnectIPUploadInstantL1(t, duration)
	if pipe.Err != nil {
		t.Fatalf("pipe L1: %v", pipe.Err)
	}

	streamDrop := http3.StreamDatagramQueueDropTotal() - streamDropBefore
	rcvDrop := quic.DatagramReceiveQueueDropTotal() - rcvDropBefore
	ratio := nativeMbps / pipe.Mbps

	t.Logf("localize upload obs: pipe=%.1f native=%.1f ratio=%.2f stream_drops=%d rcv_drops=%d",
		pipe.Mbps, nativeMbps, ratio, streamDrop, rcvDrop)
	t.Logf("hint: %s", masque.ExportConnectIPUploadNativeHint(pipe.Mbps, nativeMbps))

	if streamDrop > 0 || rcvDrop > 0 {
		t.Fatalf("datagram drops during upload: stream=%d rcv=%d — fix ingress/queue before Docker",
			streamDrop, rcvDrop)
	}
}
