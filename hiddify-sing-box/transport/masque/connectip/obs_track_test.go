package connectip

import (
	"errors"
	"sync/atomic"
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

func TestObsTrackDisabledWhenEventsOff(t *testing.T) {
	t.Parallel()
	var called atomic.Bool
	SetObs(Obs{
		EventsEnabled: func() bool { return false },
		OnPacketRx:    func(int) { called.Store(true) },
	})
	t.Cleanup(func() { SetObs(Obs{}) })

	TrackPacketRx(100)
	if called.Load() {
		t.Fatal("expected no hook when EventsEnabled is false")
	}
}

var errTestObsTrack = errors.New("obs_track_test")
