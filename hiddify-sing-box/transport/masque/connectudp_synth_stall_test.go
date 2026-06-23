package masque

// Shared fail-fast stall guards for CONNECT-UDP synth benches.
// H3 SetWriteDeadline is a no-op on datagram WriteTo — never rely on deadline alone.

import (
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing-box/transport/masque/connectudp"
)

// connectUDPSynthBenchWallDeadline is the hard wall for one bench leg (duration + teardown slack).
func connectUDPSynthBenchWallDeadline(bench time.Duration) time.Time {
	return time.Now().Add(bench + connectUDPSynthStabilityWallSlack)
}

func writeToWithStallGuard(tb testing.TB, pkt net.PacketConn, p []byte, addr net.Addr, stall time.Duration) error {
	tb.Helper()
	if pw, ok := pkt.(interface {
		WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error
	}); ok {
		return writePacketWithStallGuard(tb, pkt, pw, p, M.SocksaddrFromNet(addr), stall)
	}
	type res struct {
		n   int
		err error
	}
	ch := make(chan res, 1)
	go func() {
		n, err := pkt.WriteTo(p, addr)
		ch <- res{n, err}
	}()
	select {
	case r := <-ch:
		if r.err != nil {
			return r.err
		}
		if r.n == 0 && len(p) > 0 {
			return fmt.Errorf("WriteTo returned 0 bytes")
		}
		return nil
	case <-time.After(stall):
		_ = pkt.Close() // unblock stuck WriteTo goroutine (fail-fast tests must not leak)
		return fmt.Errorf("WriteTo stalled >%v (H3 SetWriteDeadline is no-op on datagram path)", stall)
	}
}

func writePacketWithStallGuard(tb testing.TB, pkt net.PacketConn, pw interface {
	WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error
}, p []byte, dest M.Socksaddr, stall time.Duration) error {
	tb.Helper()
	type res struct {
		err error
	}
	ch := make(chan res, 1)
	go func() {
		headroom := connectudp.ProbePacketHeadroom(pkt, dest)
		packetBuf := buf.NewSize(headroom + len(p))
		packetBuf.Resize(headroom, len(p))
		copy(packetBuf.Bytes(), p)
		err := pw.WritePacket(packetBuf, dest)
		if err != nil {
			packetBuf.Release()
		}
		ch <- res{err: err}
	}()
	select {
	case r := <-ch:
		return r.err
	case <-time.After(stall):
		_ = pkt.Close()
		return fmt.Errorf("WritePacket stalled >%v (H3 SetWriteDeadline is no-op on datagram path)", stall)
	}
}

func readFromWithStallGuard(tb testing.TB, pkt net.PacketConn, buf []byte, stall time.Duration) (int, net.Addr, error) {
	tb.Helper()
	type res struct {
		n    int
		addr net.Addr
		err  error
	}
	ch := make(chan res, 1)
	go func() {
		n, addr, err := pkt.ReadFrom(buf)
		ch <- res{n, addr, err}
	}()
	select {
	case r := <-ch:
		return r.n, r.addr, r.err
	case <-time.After(stall):
		_ = pkt.Close()
		return 0, nil, fmt.Errorf("ReadFrom stalled >%v", stall)
	}
}

func readProbeWithStallGuard(tb testing.TB, pkt net.PacketConn, buf []byte, wantRun uint32, wantSeq uint64, stall time.Duration) error {
	tb.Helper()
	deadline := time.Now().Add(stall)
	for {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return fmt.Errorf("ReadFrom stalled >%v waiting run=%d seq=%d", stall, wantRun, wantSeq)
		}
		n, _, err := readFromWithStallGuard(tb, pkt, buf, remaining)
		if err != nil {
			return err
		}
		gotSeq, gotRun, ok := connectudp.ParseProbeHeader(buf[:n])
		if !ok {
			continue
		}
		if gotRun == wantRun && gotSeq == wantSeq {
			return nil
		}
	}
}

// primeUDPBench sends one fountain/prime datagram with fail-fast stall guard (H3 WriteTo ignores deadline).
func primeUDPBench(tb testing.TB, pkt net.PacketConn, addr net.Addr) {
	tb.Helper()
	prime := make([]byte, connectudp.DefaultBenchUDPPayloadLen)
	if err := writeToWithStallGuard(tb, pkt, prime, addr, connectUDPSynthUploadWriteStall); err != nil {
		tb.Fatalf("prime WriteTo: %v", err)
	}
	time.Sleep(50 * time.Millisecond)
}

// primeUDPBenchErr is primeUDPBench for bench helpers that return errors.
func primeUDPBenchErr(tb testing.TB, pkt net.PacketConn, addr net.Addr) error {
	tb.Helper()
	prime := make([]byte, connectudp.DefaultBenchUDPPayloadLen)
	if err := writeToWithStallGuard(tb, pkt, prime, addr, connectUDPSynthUploadWriteStall); err != nil {
		return fmt.Errorf("prime WriteTo: %w", err)
	}
	time.Sleep(50 * time.Millisecond)
	return nil
}

// TestConnectUDPSynthFailFastWallContract locks per-op stall and per-leg wall (no package hang on deadlock).
func TestConnectUDPSynthFailFastWallContract(t *testing.T) {
	t.Parallel()
	if connectUDPSynthUploadWriteStall > time.Second {
		t.Fatalf("upload write stall %v must be <= 1s (fail fast)", connectUDPSynthUploadWriteStall)
	}
	maxLeg := connectUDPSynthProdBenchDuration + connectUDPSynthStabilityWallSlack
	if maxLeg > 10*time.Second {
		t.Fatalf("synth bench max wall %v must be <= 10s per leg", maxLeg)
	}
}
