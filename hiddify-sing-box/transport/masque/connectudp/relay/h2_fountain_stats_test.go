package relay

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"
)

type scriptedDownlinkAppender struct {
	appendN   int
	flushN    int
	flushErr  error
	appendErr error
}

func (s *scriptedDownlinkAppender) WriteUDPPayloadAsCapsules(udpPayload []byte) error {
	return s.AppendUDPPayloadAsCapsules(udpPayload)
}

func (s *scriptedDownlinkAppender) AppendUDPPayloadAsCapsules(udpPayload []byte) error {
	if s.appendErr != nil {
		return s.appendErr
	}
	s.appendN++
	return nil
}

func (s *scriptedDownlinkAppender) FlushPending() error {
	s.flushN++
	return s.flushErr
}

// TestH2FountainStatsOutAfterFlush covers AUDIT A6 / TASKS F0.3.
func TestH2FountainStatsOutAfterFlush(t *testing.T) {
	EnableRelayStatsForBench()
	t.Cleanup(ResetUDPRelayStats)

	peer, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()

	conn, err := net.DialUDP("udp", nil, peer.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	t.Run("success_out_after_flush", func(t *testing.T) {
		ResetUDPRelayStats()
		dl := &scriptedDownlinkAppender{}
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		done := make(chan error, 1)
		go func() {
			done <- RelayH2ConnectDownlinkFountain(ctx, conn, 2048, dl)
		}()

		if _, err := peer.WriteTo([]byte("ab"), conn.LocalAddr()); err != nil {
			t.Fatal(err)
		}
		deadline := time.Now().Add(2 * time.Second)
		for time.Now().Before(deadline) {
			snap := SnapshotUDPRelayStats()
			if snap.S2CDatagramOut >= 1 && dl.flushN >= 1 {
				cancel()
				<-done
				if snap.S2CUDPIn < 1 {
					t.Fatalf("s2c_udp_in=%d", snap.S2CUDPIn)
				}
				if dl.appendN < 1 {
					t.Fatalf("appendN=%d", dl.appendN)
				}
				return
			}
			time.Sleep(5 * time.Millisecond)
		}
		cancel()
		<-done
		t.Fatalf("timeout waiting for s2c_out; snap=%+v append=%d flush=%d", SnapshotUDPRelayStats(), dl.appendN, dl.flushN)
	})

	t.Run("flush_fail_no_out", func(t *testing.T) {
		ResetUDPRelayStats()
		dl := &scriptedDownlinkAppender{flushErr: errors.New("flush failed")}
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		done := make(chan error, 1)
		go func() {
			done <- RelayH2ConnectDownlinkFountain(ctx, conn, 2048, dl)
		}()

		if _, err := peer.WriteTo([]byte("cd"), conn.LocalAddr()); err != nil {
			t.Fatal(err)
		}
		var errOut error
		select {
		case errOut = <-done:
		case <-time.After(2 * time.Second):
			cancel()
			errOut = <-done
			t.Fatal("timeout")
		}
		if errOut == nil {
			t.Fatal("expected flush error")
		}
		snap := SnapshotUDPRelayStats()
		if snap.S2CDatagramOut != 0 {
			t.Fatalf("s2c_out=%d want 0 after flush fail", snap.S2CDatagramOut)
		}
		if snap.S2CDropSendFail < 1 {
			t.Fatalf("s2c_drop_send=%d want >=1", snap.S2CDropSendFail)
		}
	})
}
