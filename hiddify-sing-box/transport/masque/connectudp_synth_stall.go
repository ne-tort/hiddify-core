package masque

// Shared fail-fast stall guards for CONNECT-UDP synth benches.
// H3 SetWriteDeadline is a no-op on datagram WriteTo — never rely on deadline alone.

import (
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/sagernet/sing-box/transport/masque/connectudp"
	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
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
		return fmt.Errorf("WriteTo stalled >%v (H3 SetWriteDeadline is no-op on datagram path)", stall)
	}
}

// writeToBenchUpload sends on unlimited synth benches without per-packet goroutine overhead.
// Stall guard stays on paced/stability paths and GATE unlimited hammer (gateFailFast).
func writeToBenchUpload(pkt net.PacketConn, p []byte, addr net.Addr) error {
	if pw, ok := pkt.(interface {
		WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error
	}); ok {
		headroom := connectudp.ProbePacketHeadroom(pkt, M.SocksaddrFromNet(addr))
		packetBuf := buf.NewSize(headroom + len(p))
		packetBuf.Resize(headroom, len(p))
		copy(packetBuf.Bytes(), p)
		return pw.WritePacket(packetBuf, M.SocksaddrFromNet(addr))
	}
	n, err := pkt.WriteTo(p, addr)
	if err != nil {
		return err
	}
	if n == 0 && len(p) > 0 {
		return fmt.Errorf("WriteTo returned 0 bytes")
	}
	return nil
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

// readFromBenchDownload receives on unlimited synth benches without per-packet goroutine overhead.
// Stall guard stays on paced/stability paths (parity writeToBenchUpload).
func readFromBenchDownload(pkt net.PacketConn, buf []byte) (int, net.Addr, error) {
	return pkt.ReadFrom(buf)
}

// primeFountainReceiveBenchErr primes a UDP fountain for S2C-only receive benches (no stall-guard goroutine on WriteTo).
func primeFountainReceiveBenchErr(tb testing.TB, pkt net.PacketConn, addr net.Addr) error {
	tb.Helper()
	prime := make([]byte, connectudp.DefaultBenchUDPPayloadLen)
	if err := writeToBenchUpload(pkt, prime, addr); err != nil {
		return fmt.Errorf("prime WriteTo: %w", err)
	}
	connectudp.FlushPacketConnWrites(pkt)
	_ = connectudp.DrainPacketConnUpload(pkt, 200*time.Millisecond)
	// Fountain blast + server proxyConnReceive need a tick after first C2S (quic wake / onward UDP).
	time.Sleep(100 * time.Millisecond)
	return nil
}
