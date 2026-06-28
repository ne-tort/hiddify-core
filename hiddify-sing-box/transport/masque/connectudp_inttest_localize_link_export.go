package masque

import (
	"testing"
	"time"

	"github.com/sagernet/sing-box/transport/masque/connectudp"
)

func InttestConnectUDPLocalizeInstantRoundtrip(t *testing.T) {
	const duration = 400 * time.Millisecond
	bytes, mbps, err := benchConnectUDPRoundtrip(t, instantDatagramLink{}, duration)
	if err != nil {
		t.Fatalf("connect-udp localize L1 roundtrip: %v", err)
	}
	t.Logf("connect-udp localize L1 roundtrip: %.1f Mbit/s (%d bytes)", mbps, bytes)
	if mbps < connectUDPLocalizeFastMbps {
		t.Fatalf("L1 roundtrip slow: %.1f Mbit/s (want >= %.0f)", mbps, connectUDPLocalizeFastMbps)
	}
}

func InttestConnectUDPLocalizeWindowedRoundtrip(t *testing.T) {
	const duration = localizeBenchDuration
	bytes, mbps, err := benchConnectUDPRoundtrip(t, benchWindowedDatagramLink(), duration)
	if err != nil {
		t.Fatalf("connect-udp localize L3 roundtrip: %v", err)
	}
	t.Logf("connect-udp localize L3 windowed roundtrip: %.1f Mbit/s (%d bytes)", mbps, bytes)
	if bytes < localizeBenchMinBytes {
		t.Fatalf("L3 roundtrip=%d bytes too small for windowed datagram profiling", bytes)
	}
	if mbps < connectUDPLocalizeCeilingMin || mbps > connectUDPLocalizeCeilingMax {
		t.Fatalf("L3 windowed roundtrip: %.1f Mbit/s (want %.0f–%.0f)", mbps, connectUDPLocalizeCeilingMin, connectUDPLocalizeCeilingMax)
	}
}

func InttestConnectUDPLocalizeBurstUpload(t *testing.T) {
	const duration = localizeBenchDuration
	bytes, mbps, err := benchConnectUDPUpload(t, instantDatagramLink{}, duration, 0, connectudp.DefaultBenchUDPPayloadLen)
	if err != nil {
		t.Fatalf("connect-udp localize burst upload: %v", err)
	}
	t.Logf("connect-udp localize burst upload: %.1f Mbit/s (%d bytes)", mbps, bytes)
	if mbps < connectUDPLocalizeBurstMinMbps {
		t.Fatalf("burst upload slow: %.1f Mbit/s (want >= %.0f)", mbps, connectUDPLocalizeBurstMinMbps)
	}
}

func InttestConnectUDPLocalizePacedUpload(t *testing.T) {
	const duration = localizeBenchDuration
	bytes, mbps, err := benchConnectUDPUpload(
		t,
		instantDatagramLink{},
		duration,
		dockerBenchUDPTargetMbit,
		connectudp.DefaultBenchUDPPayloadLen,
	)
	if err != nil {
		t.Fatalf("connect-udp localize paced upload: %v", err)
	}
	t.Logf("connect-udp localize paced upload: %.1f Mbit/s (%d bytes)", mbps, bytes)
	if bytes < localizeBenchMinBytes/4 {
		t.Fatalf("paced upload=%d bytes too small for profiling", bytes)
	}
	if mbps < connectUDPLocalizePacedMinMbps || mbps > connectUDPLocalizePacedMaxMbps {
		t.Fatalf(
			"paced upload: %.1f Mbit/s (want %.1f–%.1f in-proc band at target %.0f Mbit/s)",
			mbps,
			connectUDPLocalizePacedMinMbps,
			connectUDPLocalizePacedMaxMbps,
			dockerBenchUDPTargetMbit,
		)
	}
}

func InttestConnectUDPLocalizeWindowedPacedUpload(t *testing.T) {
	const duration = localizeBenchDuration
	bytes, mbps, err := benchConnectUDPUpload(
		t,
		benchWindowedDatagramLink(),
		duration,
		dockerBenchUDPTargetMbit,
		connectudp.DefaultBenchUDPPayloadLen,
	)
	if err != nil {
		t.Fatalf("connect-udp localize windowed paced upload: %v", err)
	}
	expectedDocker := connectudp.ExpectedPacedGoodputMbit(dockerBenchUDPTargetMbit)
	minDocker := connectudp.MinPacedGoodputMbit(dockerBenchUDPTargetMbit)
	t.Logf(
		"connect-udp localize windowed paced upload: %.1f Mbit/s (%d bytes); docker calibrated %.2f floor %.2f",
		mbps, bytes, expectedDocker, minDocker,
	)
	if bytes < localizeBenchMinBytes/8 {
		t.Fatalf("windowed paced upload=%d bytes too small for profiling", bytes)
	}
	if mbps < connectUDPLocalizePacedMinMbps || mbps > connectUDPLocalizePacedMaxMbps {
		t.Fatalf(
			"windowed paced upload: %.1f Mbit/s (want %.1f–%.1f in-proc band at target %.0f Mbit/s; docker KPI ~%.2f)",
			mbps,
			connectUDPLocalizePacedMinMbps,
			connectUDPLocalizePacedMaxMbps,
			dockerBenchUDPTargetMbit,
			expectedDocker,
		)
	}
}

func InttestConnectUDPLocalizeBurstVsPacedContract(t *testing.T) {
	t.Parallel()
	if connectUDPLocalizeBurstMinMbps <= connectUDPLocalizePacedMaxMbps {
		t.Fatalf("burst min %.0f must exceed paced max %.0f", connectUDPLocalizeBurstMinMbps, connectUDPLocalizePacedMaxMbps)
	}
	pace := connectudp.PaceInterval(connectudp.DefaultBenchUDPPayloadLen, dockerBenchUDPTargetMbit)
	if pace <= 0 {
		t.Fatal("expected non-zero pace interval for docker target")
	}
	if got := connectudp.PaceInterval(connectudp.DefaultBenchUDPPayloadLen, 0); got != 0 {
		t.Fatalf("burst pace interval = %v want 0", got)
	}
}
