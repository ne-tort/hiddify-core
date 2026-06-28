package masque

// Localize L1/L3 bench helpers (in-process HTTP/3 proxy + windowed QUIC link).

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/netip"
	"testing"
	"time"

	"github.com/sagernet/sing-box/transport/masque/connectudp"
	M "github.com/sagernet/sing/common/metadata"
)

func benchConnectUDPRoundtrip(t *testing.T, link datagramTransportLink, duration time.Duration) (int64, float64, error) {
	t.Helper()
	echo := runUDPEcho(t, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	echoAddr := echo.LocalAddr().(*net.UDPAddr)

	proxyPort := startInProcessMasqueUDPProxy(t, func(mux *http.ServeMux, proxyPort int) {
		registerMasqueUDPProxyHandler(t, mux, proxyPort)
	})

	waitCtx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()

	opts := ClientOptions{
		Server:              "127.0.0.1",
		ServerPort:          uint16(proxyPort),
		MasqueQUICCryptoTLS: &tls.Config{InsecureSkipVerify: true},
	}
	if dial := link.quicDialOverride(); dial != nil {
		opts.QUICDial = dial
	}

	session, err := (CoreClientFactory{}).NewSession(waitCtx, opts)
	if err != nil {
		return 0, 0, err
	}
	defer func() { _ = session.Close() }()

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

func benchConnectUDPUpload(
	t *testing.T,
	link datagramTransportLink,
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

	proxyPort := startInProcessMasqueUDPProxy(t, func(mux *http.ServeMux, proxyPort int) {
		registerMasqueUDPProxyHandler(t, mux, proxyPort)
	})

	waitCtx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()

	opts := ClientOptions{
		Server:              "127.0.0.1",
		ServerPort:          uint16(proxyPort),
		MasqueQUICCryptoTLS: &tls.Config{InsecureSkipVerify: true},
	}
	if dial := link.quicDialOverride(); dial != nil {
		opts.QUICDial = dial
	}

	session, err := (CoreClientFactory{}).NewSession(waitCtx, opts)
	if err != nil {
		return 0, 0, err
	}
	defer func() { _ = session.Close() }()

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
	deadline := time.Now().Add(duration)
	wall := connectUDPSynthBenchWallDeadline(duration)
	var sent int64
	var paceSlot time.Time
	for time.Now().Before(deadline) {
		if time.Now().After(wall) {
			break
		}
		if err := writeToWithStallGuard(t, pkt, payload, sinkAddr, connectUDPSynthUploadWriteStall); err != nil {
			if sent > 0 {
				break
			}
			return 0, 0, err
		}
		sent += int64(len(payload))
		connectudp.PaceSleepUntil(&paceSlot, payloadLen, targetMbit)
	}
	secs := duration.Seconds()
	if secs <= 0 {
		secs = 1
	}
	return sent, float64(sent*8) / secs / 1e6, nil
}

