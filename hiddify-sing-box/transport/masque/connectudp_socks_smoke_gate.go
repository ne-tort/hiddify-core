package masque

import (
	"context"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/route"
	"github.com/sagernet/sing-box/transport/masque/connectudp"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/protocol/socks"
)

const connectUDPSocksSmokePayload = "connect-udp-socks-smoke-v1"

// gateConnectUDPSocksProbeEcho verifies SOCKS5 UDP ASSOCIATE → masque endpoint → echo (prod stack shape).
func gateConnectUDPSocksProbeEcho(t *testing.T, layer string) {
	t.Helper()
	echo := runUDPEcho(t, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	echoAddr := echo.LocalAddr().(*net.UDPAddr)

	var session ClientSession
	switch layer {
	case "h3":
		proxyPort := startInProcessMasqueUDPProxy(t, func(mux *http.ServeMux, proxyPort int) {
			registerMasqueUDPProxyHandler(t, mux, proxyPort)
		})
		session = startConnectUDPMasqueSession(t, proxyPort)
	case "h2":
		proxyPort := startInProcessH2UDPConnectProxy(t)
		session = startConnectUDPH2MasqueSession(t, proxyPort)
	default:
		t.Fatalf("unknown layer %q", layer)
	}

	out := &masqueSessionOutbound{
		Adapter: outbound.NewAdapter(constant.TypeMasque, "masque-out", []string{N.NetworkTCP, N.NetworkUDP}, nil),
		sess:    session,
	}
	cm := route.NewConnectionManager(log.StdLogger())
	t.Cleanup(func() { _ = cm.Close() })
	router := &directMasqueRouter{cm: cm, dialer: out}
	socksPort := startSocks5AssociateRelay(t, router, constant.TypeSOCKS)

	dialer := socks.NewClient(N.SystemDialer, M.ParseSocksaddrHostPort("127.0.0.1", socksPort), socks.Version5, "", "")
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	t.Cleanup(cancel)

	pkt, err := dialer.ListenPacket(ctx, M.ParseSocksaddrHostPort(echoAddr.IP.String(), uint16(echoAddr.Port)))
	if err != nil {
		t.Fatalf("socks udp associate listen: %v", err)
	}
	t.Cleanup(func() { _ = pkt.Close() })
	route.TuneUDPPacketConn(pkt)

	payload := []byte(connectUDPSocksSmokePayload)
	if _, err := pkt.WriteTo(payload, echoAddr); err != nil {
		t.Fatalf("socks WriteTo: %v", err)
	}
	buf := make([]byte, len(payload)+64)
	n, _, err := pkt.ReadFrom(buf)
	if err != nil {
		t.Fatalf("socks ReadFrom: %v", err)
	}
	if string(buf[:n]) != connectUDPSocksSmokePayload {
		t.Fatalf("socks echo mismatch: got %q want %q", buf[:n], connectUDPSocksSmokePayload)
	}
	t.Logf("GATE socks %s probe echo OK (%d B round-trip)", layer, n)
}

// gateConnectUDPSocksSequencedUpload runs a short zero-loss sequenced upload via SOCKS (WAN-paced target).
func gateConnectUDPSocksSequencedUpload(t *testing.T, layer string) {
	t.Helper()
	payloadLen := connectudp.DefaultBenchUDPPayloadLen
	dur := 2 * time.Second
	target := dockerBenchUDPTargetMbit

	var got connectUDPPacedBenchResult
	switch layer {
	case "h3":
		got = benchConnectUDPPacedSinkGoodput(t, true, dur, target)
	case "h2":
		got = benchConnectUDPH2PacedSinkGoodput(t, true, dur, target)
	default:
		t.Fatalf("unknown layer %q", layer)
	}
	if !got.stats.BurstZeroLossOK(payloadLen, connectudp.DefaultBurstMinRxRatio) {
		t.Fatalf("%s socks paced upload: zero-loss+seq set fail rx=%d/%d loss=%.2f%% seq_ok=%v",
			layer, got.stats.RxPkts, got.sentPkts, got.stats.LossPct, got.stats.SeqSetOK)
	}
	minFloor := connectudp.MinPacedGoodputMbit(target) * 0.5 // short 2s leg — anti-regression only
	if got.mbps < minFloor {
		t.Fatalf("%s socks paced goodput %.2f Mbit/s < floor %.2f", layer, got.mbps, minFloor)
	}
	t.Logf("GATE socks %s paced upload: %.2f Mbit/s rx=%d/%d seq_ok=%v",
		layer, got.mbps, got.stats.RxPkts, got.sentPkts, got.stats.SeqSetOK)
}
