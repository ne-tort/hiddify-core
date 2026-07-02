package relay

import (
	"context"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/transport/masque/connectudp/frame"
)

type isolatedDatagramSink struct {
	bytes atomic.Uint64
	pkts  atomic.Uint64
}

func (s *isolatedDatagramSink) SendDatagram(p []byte) error {
	if len(p) <= len(frame.ContextIDZeroWire) {
		return nil
	}
	s.bytes.Add(uint64(len(p) - len(frame.ContextIDZeroWire)))
	s.pkts.Add(1)
	return nil
}

// benchIsolatedH3RelayS2C measures proxyConnReceive goodput with a UDP flood source (B1 server-only attribution).
func benchIsolatedH3RelayS2C(tb testing.TB, payloadLen int, duration time.Duration) float64 {
	tb.Helper()
	if payloadLen <= 0 {
		payloadLen = 512
	}
	if duration <= 0 {
		duration = 2 * time.Second
	}

	relayConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		tb.Fatal(err)
	}
	defer relayConn.Close()

	sink := &isolatedDatagramSink{}
	relayDone := make(chan error, 1)
	go func() {
		relayDone <- proxyConnReceive(context.Background(), relayConn, sink)
	}()

	floodConn, err := net.DialUDP("udp4", nil, relayConn.LocalAddr().(*net.UDPAddr))
	if err != nil {
		tb.Fatal(err)
	}
	defer floodConn.Close()

	payload := make([]byte, payloadLen)
	for i := range payload {
		payload[i] = byte(i)
	}

	deadline := time.Now().Add(duration)
	for time.Now().Before(deadline) {
		if _, err := floodConn.Write(payload); err != nil {
			tb.Fatal(err)
		}
	}
	_ = relayConn.Close()
	<-relayDone

	secs := duration.Seconds()
	if secs <= 0 {
		return 0
	}
	return float64(sink.bytes.Load()*8) / secs / 1e6
}

// TestLocalizeConnectUDPRelayIsolatedS2C attributes fountain S2C throughput to server relay only (UDP-BENCH-GAPS B1).
func TestLocalizeConnectUDPRelayIsolatedS2C(t *testing.T) {
	t.Parallel()
	const duration = 2 * time.Second
	mbps := benchIsolatedH3RelayS2C(t, 512, duration)
	t.Logf("LOCALIZE B1 isolated h3 relay S2C: %.1f Mbit/s (%v @512B)", mbps, duration)
	if mbps < 200 {
		t.Fatalf("isolated relay S2C %.1f Mbit/s < 200 — server relay regression", mbps)
	}
}
