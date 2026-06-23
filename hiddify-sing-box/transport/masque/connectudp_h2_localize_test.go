package masque

// H2 CONNECT-UDP localize mirror: ListenPacket path on instant + windowed TCP link (parity with connect_udp_localize_test.go H3).

import (
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/sagernet/sing-box/transport/masque/connectudp"
	M "github.com/sagernet/sing/common/metadata"
)

type windowedH2Link struct {
	bidi bidiLink
}

func benchWindowedH2Link() windowedH2Link {
	return windowedH2Link{bidi: benchWindowedBidiLink()}
}

func (w windowedH2Link) wrapTCP(c net.Conn) net.Conn {
	return w.bidi.wrap(c)
}

func benchConnectUDPH2Roundtrip(t *testing.T, link h2TransportLink, duration time.Duration) (int64, float64, error) {
	t.Helper()
	echo := runUDPEcho(t, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	echoAddr := echo.LocalAddr().(*net.UDPAddr)

	proxyPort := startInProcessH2UDPConnectProxy(t)
	session, waitCtx := newH2ConnectUDPSession(t, proxyPort, link)

	pkt, err := session.ListenPacket(waitCtx, M.Socksaddr{
		Addr: netip.MustParseAddr(echoAddr.IP.String()),
		Port: uint16(echoAddr.Port),
	})
	if err != nil {
		return 0, 0, err
	}
	defer func() { _ = pkt.Close() }()

	payload := make([]byte, 1200)
	for i := range payload {
		payload[i] = byte(i % 251)
	}
	buf := make([]byte, 2048)
	deadline := time.Now().Add(duration)
	var total int64
	for time.Now().Before(deadline) {
		_ = pkt.SetWriteDeadline(time.Now().Add(2 * time.Second))
		if _, err := pkt.WriteTo(payload, echoAddr); err != nil {
			if total > 0 {
				break
			}
			return 0, 0, err
		}
		_ = pkt.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, _, err := pkt.ReadFrom(buf)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() && total > 0 {
				break
			}
			if total > 0 {
				break
			}
			return 0, 0, err
		}
		total += int64(n) * 2
	}
	secs := duration.Seconds()
	if secs <= 0 {
		secs = 1
	}
	return total, float64(total*8) / secs / 1e6, nil
}

func benchConnectUDPH2Upload(
	t *testing.T,
	link h2TransportLink,
	duration time.Duration,
	targetMbit float64,
	payloadLen int,
) (int64, float64, error) {
	t.Helper()
	if payloadLen <= 0 {
		payloadLen = connectudp.DefaultBenchUDPPayloadLen
	}
	sink, _ := runUDPSink(t, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	sinkAddr := sink.LocalAddr().(*net.UDPAddr)

	proxyPort := startInProcessH2UDPConnectProxy(t)
	session, waitCtx := newH2ConnectUDPSession(t, proxyPort, link)

	pkt, err := session.ListenPacket(waitCtx, M.Socksaddr{
		Addr: netip.MustParseAddr(sinkAddr.IP.String()),
		Port: uint16(sinkAddr.Port),
	})
	if err != nil {
		return 0, 0, err
	}
	defer func() { _ = pkt.Close() }()

	payload := make([]byte, payloadLen)
	for i := range payload {
		payload[i] = byte(i % 251)
	}
	pace := connectudp.PaceInterval(payloadLen, targetMbit)
	deadline := time.Now().Add(duration)
	var sent int64
	for time.Now().Before(deadline) {
		_ = pkt.SetWriteDeadline(time.Now().Add(2 * time.Second))
		n, err := pkt.WriteTo(payload, sinkAddr)
		if err != nil {
			if sent > 0 {
				break
			}
			return 0, 0, err
		}
		sent += int64(n)
		if pace > 0 {
			time.Sleep(pace)
		}
	}
	secs := duration.Seconds()
	if secs <= 0 {
		secs = 1
	}
	return sent, float64(sent*8) / secs / 1e6, nil
}

// TestConnectUDPH2LocalizeInstantRoundtrip benches H2 CONNECT-UDP echo on an instant in-process link.
func TestConnectUDPH2LocalizeInstantRoundtrip(t *testing.T) {
	const duration = 400 * time.Millisecond
	bytes, mbps, err := benchConnectUDPH2Roundtrip(t, instantH2Link{}, duration)
	if err != nil {
		t.Fatalf("connect-udp h2 localize L1 roundtrip: %v", err)
	}
	t.Logf("connect-udp h2 localize L1 roundtrip: %.1f Mbit/s (%d bytes)", mbps, bytes)
	if mbps < connectUDPLocalizeFastMbps {
		t.Fatalf("H2 L1 roundtrip slow: %.1f Mbit/s (want >= %.0f)", mbps, connectUDPLocalizeFastMbps)
	}
}

// TestConnectUDPH2LocalizeWindowedRoundtrip benches H2 CONNECT-UDP with bench-shaped TCP window (~64 KiB / 35 ms RTT).
func TestConnectUDPH2LocalizeWindowedRoundtrip(t *testing.T) {
	const duration = localizeBenchDuration
	bytes, mbps, err := benchConnectUDPH2Roundtrip(t, benchWindowedH2Link(), duration)
	if err != nil {
		t.Fatalf("connect-udp h2 localize L3 roundtrip: %v", err)
	}
	t.Logf("connect-udp h2 localize L3 windowed roundtrip: %.1f Mbit/s (%d bytes)", mbps, bytes)
	if bytes < localizeBenchMinBytes {
		t.Fatalf("H2 L3 roundtrip=%d bytes too small for windowed profiling", bytes)
	}
	if mbps < connectUDPLocalizeCeilingMin || mbps > connectUDPLocalizeCeilingMax {
		t.Fatalf("H2 L3 windowed roundtrip: %.1f Mbit/s (want %.0f–%.0f)", mbps, connectUDPLocalizeCeilingMin, connectUDPLocalizeCeilingMax)
	}
}

// TestConnectUDPH2LocalizeBurstUpload benches unlimited one-way H2 upload on instant link.
func TestConnectUDPH2LocalizeBurstUpload(t *testing.T) {
	const duration = localizeBenchDuration
	bytes, mbps, err := benchConnectUDPH2Upload(t, instantH2Link{}, duration, 0, connectudp.DefaultBenchUDPPayloadLen)
	if err != nil {
		t.Fatalf("connect-udp h2 localize burst upload: %v", err)
	}
	t.Logf("connect-udp h2 localize burst upload: %.1f Mbit/s (%d bytes)", mbps, bytes)
	if mbps < connectUDPLocalizeBurstMinMbps {
		t.Fatalf("H2 burst upload slow: %.1f Mbit/s (want >= %.0f)", mbps, connectUDPLocalizeBurstMinMbps)
	}
}

// TestConnectUDPH2LocalizePacedUpload benches docker-aligned paced H2 upload (8 Mbit/s target) on instant link.
func TestConnectUDPH2LocalizePacedUpload(t *testing.T) {
	const duration = localizeBenchDuration
	bytes, mbps, err := benchConnectUDPH2Upload(
		t,
		instantH2Link{},
		duration,
		dockerBenchUDPTargetMbit,
		connectudp.DefaultBenchUDPPayloadLen,
	)
	if err != nil {
		t.Fatalf("connect-udp h2 localize paced upload: %v", err)
	}
	t.Logf("connect-udp h2 localize paced upload: %.1f Mbit/s (%d bytes)", mbps, bytes)
	if bytes < localizeBenchMinBytes/4 {
		t.Fatalf("H2 paced upload=%d bytes too small for profiling", bytes)
	}
	if mbps < connectUDPLocalizePacedMinMbps || mbps > connectUDPLocalizePacedMaxMbps {
		t.Fatalf(
			"H2 paced upload: %.1f Mbit/s (want %.1f–%.1f in-proc band at target %.0f Mbit/s)",
			mbps,
			connectUDPLocalizePacedMinMbps,
			connectUDPLocalizePacedMaxMbps,
			dockerBenchUDPTargetMbit,
		)
	}
}

// TestConnectUDPH2LocalizeWindowedPacedUpload benches paced upload on windowed TCP link (in-proc band, not docker WAN KPI).
func TestConnectUDPH2LocalizeWindowedPacedUpload(t *testing.T) {
	const duration = localizeBenchDuration
	bytes, mbps, err := benchConnectUDPH2Upload(
		t,
		benchWindowedH2Link(),
		duration,
		dockerBenchUDPTargetMbit,
		connectudp.DefaultBenchUDPPayloadLen,
	)
	if err != nil {
		t.Fatalf("connect-udp h2 localize windowed paced upload: %v", err)
	}
	t.Logf("connect-udp h2 localize windowed paced upload: %.1f Mbit/s (%d bytes)", mbps, bytes)
	if bytes < localizeBenchMinBytes/8 {
		t.Fatalf("H2 windowed paced upload=%d bytes too small for profiling", bytes)
	}
	if mbps < connectUDPLocalizePacedMinMbps || mbps > connectUDPLocalizePacedMaxMbps {
		t.Fatalf(
			"H2 windowed paced upload: %.1f Mbit/s (want %.1f–%.1f in-proc band at target %.0f Mbit/s)",
			mbps,
			connectUDPLocalizePacedMinMbps,
			connectUDPLocalizePacedMaxMbps,
			dockerBenchUDPTargetMbit,
		)
	}
}
