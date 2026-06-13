package connectudp

import (
	"testing"
	"time"
)

func TestPaceIntervalBurstIsZero(t *testing.T) {
	t.Parallel()
	if got := PaceInterval(DefaultBenchUDPPayloadLen, 0); got != 0 {
		t.Fatalf("PaceInterval burst = %v want 0", got)
	}
}

func TestPaceIntervalMatchesDockerTarget(t *testing.T) {
	t.Parallel()
	got := PaceInterval(DefaultBenchUDPPayloadLen, DefaultBenchUDPTargetMbit)
	want := time.Duration(float64(DefaultBenchUDPPayloadLen*8) / (DefaultBenchUDPTargetMbit * 1_000_000.0) * float64(time.Second))
	if got != want {
		t.Fatalf("PaceInterval = %v want %v", got, want)
	}
}

func TestPaceIntervalGoodputCalibration(t *testing.T) {
	t.Parallel()
	const observed = 6.75
	got := ExpectedPacedGoodputMbit(DefaultBenchUDPTargetMbit)
	if got < 6.66 || got > observed {
		t.Fatalf("ExpectedPacedGoodputMbit(8) = %.3f want ~6.66–%.2f", got, observed)
	}
	if MinPacedGoodputMbit(DefaultBenchUDPTargetMbit) != DockerPacedUDPMinUpMbit {
		t.Fatalf("MinPacedGoodputMbit(8) = %v want %v", MinPacedGoodputMbit(DefaultBenchUDPTargetMbit), DockerPacedUDPMinUpMbit)
	}
}

func TestPaceIntervalCalibrationSweep(t *testing.T) {
	t.Parallel()
	targets := []float64{4, 8, 12, 16}
	for _, target := range targets {
		expected := ExpectedPacedGoodputMbit(target)
		floor := MinPacedGoodputMbit(target)
		if expected <= floor {
			t.Fatalf("target=%.0f: expected %.3f <= floor %.3f", target, expected, floor)
		}
		if floor/target != DockerPacedUDPMinUpMbit/DefaultBenchUDPTargetMbit {
			t.Fatalf("target=%.0f: floor ratio drift", target)
		}
	}
}
