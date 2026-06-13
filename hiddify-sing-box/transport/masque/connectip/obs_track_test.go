package connectip

import (
	"errors"
	"testing"
)

func TestObsTrackPacketPlaneHooks(t *testing.T) {
	t.Parallel()
	var rxN, txLen, ptb int
	var readErr, writeErr error
	var writeCeiling bool
	SetObs(Obs{
		EventsEnabled: func() bool { return true },
		OnPacketRx:    func(n int) { rxN = n },
		OnPacketTx:    func(n int) { txLen = n },
		OnPacketReadExit: func(err error) {
			readErr = err
		},
		OnPacketWriteFail: func(err error, ceiling bool) {
			writeErr = err
			writeCeiling = ceiling
		},
		OnPacketPTBRx: func() { ptb++ },
		ClassifyWriteError: func(err error) string {
			if errors.Is(err, errTestObsTrack) {
				return "test_reason"
			}
			return "other"
		},
	})
	t.Cleanup(func() { SetObs(Obs{}) })

	TrackPacketRx(0)
	TrackPacketTx(0)
	TrackReadExit(nil)
	TrackWriteFail(nil, false)
	if rxN != 0 || txLen != 0 || readErr != nil || writeErr != nil || ptb != 0 {
		t.Fatal("zero/nil inputs should not invoke hooks")
	}

	TrackPacketRx(42)
	TrackPacketTx(17)
	errTest := errTestObsTrack
	TrackReadExit(errTest)
	TrackWriteFail(errTest, true)
	TrackPTBRx()

	if rxN != 42 || txLen != 17 || !errors.Is(readErr, errTest) || !errors.Is(writeErr, errTest) || !writeCeiling || ptb != 1 {
		t.Fatalf("hooks: rx=%d tx=%d readErr=%v writeErr=%v ceiling=%v ptb=%d", rxN, txLen, readErr, writeErr, writeCeiling, ptb)
	}
}

func TestObsTrackServerWriteIteration(t *testing.T) {
	t.Parallel()
	var txLen, ptb int
	var writeErr error
	SetObs(Obs{
		OnPacketTx:        func(n int) { txLen = n },
		OnPacketWriteFail: func(err error, _ bool) { writeErr = err },
		OnPacketPTBRx:     func() { ptb++ },
	})
	t.Cleanup(func() { SetObs(Obs{}) })

	TrackServerWriteIteration(64, 32, nil)
	if txLen != 64 || ptb != 1 || writeErr != nil {
		t.Fatalf("success+ptb: tx=%d ptb=%d writeErr=%v", txLen, ptb, writeErr)
	}

	TrackServerWriteIteration(0, 0, errTestObsTrack)
	if !errors.Is(writeErr, errTestObsTrack) {
		t.Fatalf("write fail: %v", writeErr)
	}
}

func TestObsTrackPacketCountersWithoutObsEnv(t *testing.T) {
	t.Setenv("MASQUE_CONNECT_IP_OBS", "")
	SetObs(CounterObsHooks())
	t.Cleanup(func() { SetObs(Obs{}) })

	before := ObservabilitySnapshot()["connect_ip_packet_rx_total"].(uint64)
	TrackPacketRx(128)
	after := ObservabilitySnapshot()["connect_ip_packet_rx_total"].(uint64)
	if after != before+1 {
		t.Fatalf("packet_rx_total: before=%d after=%d want %d", before, after, before+1)
	}
}

var errTestObsTrack = errors.New("obs_track_test")
