// udp-probe: paced/burst UDP upload for MASQUE CONNECT-UDP docker bench.
// Parity with docker/masque-perf-lab/bench/udp_masque_send.py (RESULT_UDP_* stdout).
package main

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"net"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/protocol/socks"

	"github.com/sagernet/sing-box/transport/masque/connectudp"
)

func main() {
	if len(os.Args) < 5 {
		fmt.Fprintf(os.Stderr, "usage: udp-probe host port duration_sec target_mbit [payload_len] [--socks PORT]\n")
		os.Exit(2)
	}
	host := os.Args[1]
	port, err := strconv.Atoi(os.Args[2])
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid port: %v\n", err)
		os.Exit(2)
	}
	duration, err := strconv.ParseFloat(os.Args[3], 64)
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid duration: %v\n", err)
		os.Exit(2)
	}
	targetMbit, err := strconv.ParseFloat(os.Args[4], 64)
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid target_mbit: %v\n", err)
		os.Exit(2)
	}

	payloadLen := connectudp.DefaultBenchUDPPayloadLen
	if v := os.Getenv("BENCH_UDP_PAYLOAD_LEN"); v != "" {
		payloadLen, _ = strconv.Atoi(v)
	}
	var socksPort int
	for i := 5; i < len(os.Args); i++ {
		if os.Args[i] == "--socks" && i+1 < len(os.Args) {
			socksPort, _ = strconv.Atoi(os.Args[i+1])
			i++
			continue
		}
		payloadLen, _ = strconv.Atoi(os.Args[i])
	}
	if duration <= 0 || payloadLen < 32 {
		fmt.Println("RESULT_UDP_SEND_ERR=invalid args")
		os.Exit(1)
	}

	runID := uint32(0)
	if v := os.Getenv("BENCH_UDP_RUN_ID"); v != "" {
		u, _ := strconv.ParseUint(v, 10, 32)
		runID = uint32(u)
	}
	if runID == 0 {
		var b [8]byte
		_, _ = rand.Read(b[:])
		runID = crc32.ChecksumIEEE(b[:])
	}

	connectTimeout := 3 * time.Second
	if v := os.Getenv("UDP_CONNECT_TIMEOUT_SEC"); v != "" {
		if sec, err := strconv.ParseFloat(v, 64); err == nil && sec > 0 {
			connectTimeout = time.Duration(sec * float64(time.Second))
		}
	}

	pkt, destSocks, closeFn, err := openPacketConn(host, uint16(port), socksPort, connectTimeout)
	if err != nil {
		fmt.Printf("RESULT_UDP_SEND_ERR=%v\n", err)
		os.Exit(1)
	}
	defer closeFn()
	tuneProbePacketConn(pkt)

	backpressure := targetMbit <= 0 && envTruthy("BENCH_UDP_SEND_BACKPRESSURE")
	sent, pkts, elapsed, err := runSend(pkt, destSocks, duration, targetMbit, payloadLen, runID, backpressure)
	if err != nil {
		fmt.Printf("RESULT_UDP_SEND_ERR=%v\n", err)
		os.Exit(1)
	}
	fmt.Printf("RESULT_UDP_RUN_ID=%d\n", runID)
	fmt.Printf("RESULT_UDP_SENT_BYTES=%d\n", sent)
	fmt.Printf("RESULT_UDP_SENT_PKTS=%d\n", pkts)
	fmt.Printf("RESULT_UDP_SEND_SEC=%.3f\n", elapsed)
}

func envTruthy(key string) bool {
	switch os.Getenv(key) {
	case "1", "true", "yes", "TRUE", "YES":
		return true
	default:
		return false
	}
}

func openPacketConn(host string, port uint16, socksPort int, timeout time.Duration) (net.PacketConn, M.Socksaddr, func(), error) {
	dest := M.ParseSocksaddrHostPort(host, port)
	if socksPort > 0 {
		dialer := socks.NewClient(
			N.SystemDialer,
			M.ParseSocksaddrHostPort("127.0.0.1", uint16(socksPort)),
			socks.Version5,
			"",
			"",
		)
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		pkt, err := dialer.ListenPacket(ctx, dest)
		if err != nil {
			cancel()
			return nil, M.Socksaddr{}, nil, err
		}
		return pkt, dest, func() {
			_ = pkt.Close()
			cancel()
		}, nil
	}
	udp, err := net.ListenPacket("udp4", "0.0.0.0:0")
	if err != nil {
		return nil, M.Socksaddr{}, nil, err
	}
	return udp, dest, func() { _ = udp.Close() }, nil
}

func tuneProbePacketConn(conn net.PacketConn) {
	snd := 4 << 20
	if v := os.Getenv("BENCH_UDP_SNDBUF"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			snd = n
		}
	}
	tuneProbePacketConnAny(conn, snd)
}

func tuneProbePacketConnAny(conn any, snd int) {
	if conn == nil {
		return
	}
	if uc, ok := conn.(*net.UDPConn); ok {
		_ = uc.SetWriteBuffer(snd)
		_ = uc.SetReadBuffer(snd)
	}
	if up, ok := conn.(interface{ Upstream() any }); ok {
		tuneProbePacketConnAny(up.Upstream(), snd)
	}
}

func runSend(
	pkt net.PacketConn,
	dest M.Socksaddr,
	duration float64,
	targetMbit float64,
	payloadLen int,
	runID uint32,
	backpressure bool,
) (sentBytes int, sentPkts int, elapsed float64, err error) {
	payload := make([]byte, payloadLen)
	binary.BigEndian.PutUint32(payload[8:12], runID)

	deadline := time.Now().Add(time.Duration(duration * float64(time.Second)))
	start := time.Now()
	var seq uint64
	var paceSlot time.Time

	if pw, ok := pkt.(interface {
		WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error
	}); ok {
		headroom := connectudp.ProbePacketHeadroom(pkt, dest)
		var pool sync.Pool
		pool.New = func() any {
			return buf.NewSize(headroom + payloadLen)
		}
		for time.Now().Before(deadline) {
			binary.BigEndian.PutUint64(payload[0:8], seq)
			packetBuf := pool.Get().(*buf.Buffer)
			packetBuf.Resize(headroom, payloadLen)
			copy(packetBuf.Bytes(), payload)
			if werr := pw.WritePacket(packetBuf, dest); werr != nil {
				packetBuf.Release()
				return 0, 0, 0, werr
			}
			sentBytes += payloadLen
			sentPkts++
			seq++
			if targetMbit > 0 {
				connectudp.PaceSleepUntil(&paceSlot, payloadLen, targetMbit)
			} else if backpressure {
				continue
			}
		}
	} else {
		destAddr := dest.UDPAddr()
		for time.Now().Before(deadline) {
			binary.BigEndian.PutUint64(payload[0:8], seq)
			n, werr := pkt.WriteTo(payload, destAddr)
			if werr != nil {
				return 0, 0, 0, werr
			}
			sentBytes += n
			sentPkts++
			seq++
			if targetMbit > 0 {
				connectudp.PaceSleepUntil(&paceSlot, payloadLen, targetMbit)
			} else if backpressure {
				continue
			}
		}
	}
	connectudp.FlushPacketConnWrites(pkt)
	time.Sleep(200 * time.Millisecond)
	elapsed = time.Since(start).Seconds()
	if elapsed < 1e-9 {
		elapsed = 1e-9
	}
	return sentBytes, sentPkts, elapsed, nil
}
