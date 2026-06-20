package masque_test



import (

	"runtime"

	"testing"

	"time"



	"github.com/sagernet/sing-box/transport/masque"

)



// TestGATEConnectIPUploadSynthNative completes the upload synth gate with native H3 C2S.

// Native runs before pipe L1 (pipe-first starved QUIC in paired benches on Windows).

func TestGATEConnectIPUploadSynthNative(t *testing.T) {

	duration := masque.ExportLocalizeBenchDuration



	nativeMbps, _ := benchConnectIPNativeUploadH3(t, connectIPNativeSynthBenchDur)



	runtime.GC()

	time.Sleep(200 * time.Millisecond)



	pipe := masque.ExportBenchConnectIPUploadInstantL1(t, duration)

	if pipe.Err != nil {

		t.Fatalf("pipe L1: %v", pipe.Err)

	}

	t.Logf("pipe L1 upload (no QUIC): %.1f Mbit/s (after native)", pipe.Mbps)



	ratio := 0.0

	if pipe.Mbps > 0 {

		ratio = nativeMbps / pipe.Mbps

	}

	t.Logf("native H3 upload: %.1f Mbit/s; native/pipe=%.2f (min %.2f)",

		nativeMbps, ratio, masque.ExportConnectIPSynthPipeMinRatio)

	t.Logf("localization: %s", masque.ExportConnectIPUploadNativeHint(pipe.Mbps, nativeMbps))



	if nativeMbps < masque.ExportConnectIPSynthRegressionFloorUpMbps {

		t.Fatalf("native upload regression: %.1f < %.1f Mbit/s",

			nativeMbps, masque.ExportConnectIPSynthRegressionFloorUpMbps)

	}

	if ratio < masque.ExportConnectIPSynthPipeMinRatio {

		t.Fatalf("native/pipe ratio %.2f < %.2f — QUIC/datagram C2S is dominant bottleneck (Docker would not help)",

			ratio, masque.ExportConnectIPSynthPipeMinRatio)

	}

	if pipe.Mbps >= masque.ExportConnectIPSynthPipeFastMinMbps {

		t.Logf("fast-pipe native/pipe=%.2f (floor %.2f target %.2f @ pipe>=%.0f)",

			ratio, masque.ExportConnectIPSynthPipeFastFloorRatio,

			masque.ExportConnectIPSynthPipeFastTargetRatio, masque.ExportConnectIPSynthPipeFastMinMbps)

		if ratio < masque.ExportConnectIPSynthPipeFastFloorRatio {

			t.Fatalf("native/pipe %.2f < fast-pipe floor %.2f (pipe L1 %.1f) — QUIC/datagram egress gap",

				ratio, masque.ExportConnectIPSynthPipeFastFloorRatio, pipe.Mbps)

		}

		if ratio < masque.ExportConnectIPSynthPipeFastTargetRatio {

			t.Logf("OPEN: native/pipe %.2f < target %.2f — Docker connect-ip-h3-tun after synth close",

				ratio, masque.ExportConnectIPSynthPipeFastTargetRatio)

		}

	}

	if nativeMbps < masque.ExportConnectIPSynthProdMinMbps {

		t.Logf("OPEN: native upload %.1f < DoD %.0f — synth gate PASS; Docker connect-ip-h3-tun @0ms is next KPI",

			nativeMbps, masque.ExportConnectIPSynthProdMinMbps)

	}

}


