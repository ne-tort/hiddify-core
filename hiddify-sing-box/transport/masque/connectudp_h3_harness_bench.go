package masque

// H3 CONNECT-UDP client harness bench helpers (inttest export).

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/route"
	"github.com/sagernet/sing-box/transport/masque/connectudp"
	cudpclient "github.com/sagernet/sing-box/transport/masque/connectudp/client"
	cudpsplit "github.com/sagernet/sing-box/transport/masque/connectudp/split"
	h3t "github.com/sagernet/sing-box/transport/masque/h3"
	"github.com/yosida95/uritemplate/v3"
)

func dialH3ConnectUDPDirect(tb testing.TB, proxyPort int, target string) net.PacketConn {
	tb.Helper()
	clientTLS := connectUDPTestTLS.Clone()
	clientTLS.InsecureSkipVerify = true
	clientTLS.ServerName = "127.0.0.1"
	client := cudpclient.NewQUICClient(cudpclient.QUICClientConfig{
		TLSClientConfig: clientTLS,
		QUICConfig:      h3t.QUICConfigForDial(h3t.QUICDialProfile{}),
	})
	rawTpl := fmt.Sprintf("https://127.0.0.1:%d/masque/udp/{target_host}/{target_port}", proxyPort)
	tpl, err := uritemplate.New(rawTpl)
	if err != nil {
		tb.Fatalf("template: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	tb.Cleanup(cancel)
	raw, err := cudpclient.DialH3Production(ctx, nil, client, tpl, target)
	if err != nil {
		tb.Fatalf("DialH3Production: %v", err)
	}
	tb.Cleanup(func() { _ = raw.Close() })
	pkt := cudpsplit.NewDatagramSplitConn(raw, cudpsplit.DatagramSplitOptions{
		MaxPayload: connectudp.DefaultBenchUDPPayloadLen,
		HTTPLayer:  option.MasqueHTTPLayerH3,
	})
	route.TuneUDPPacketConn(pkt)
	return pkt
}

func benchConnectUDPH3DirectDownloadFountainWithProxy(
	tb testing.TB,
	register func(testing.TB, *http.ServeMux, int),
	duration time.Duration,
	payloadLen int,
) (int64, float64, error) {
	tb.Helper()
	if payloadLen <= 0 {
		payloadLen = connectudp.DefaultBenchUDPPayloadLen
	}
	fountain := startUDPFountain(tb, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	fountainAddr := fountain.LocalAddr().(*net.UDPAddr)
	proxyPort := startInProcessMasqueUDPProxy(tb, func(mux *http.ServeMux, proxyPort int) {
		register(tb, mux, proxyPort)
	})
	target := net.JoinHostPort(fountainAddr.IP.String(), strconv.Itoa(fountainAddr.Port))
	pkt := dialH3ConnectUDPDirect(tb, proxyPort, target)
	return benchConnectUDPH3FountainS2C(tb, pkt, fountainAddr, duration, payloadLen, false)
}

func benchConnectUDPH3DirectDownloadFountain(
	tb testing.TB,
	duration time.Duration,
	payloadLen int,
) (int64, float64, error) {
	return benchConnectUDPH3DirectDownloadFountainWithProxy(tb, registerMasqueUDPProxyHandler, duration, payloadLen)
}

// benchConnectUDPH3DirectUploadZeroLoss measures bidi DialH3Production upload (localize vs asymmetric ListenPacket).
func benchConnectUDPH3DirectUploadZeroLoss(
	tb testing.TB,
	duration time.Duration,
	payloadLen int,
) (float64, connectudp.SequencedStats, error) {
	tb.Helper()
	const runID = uint32(0xC0FFEE03)
	if payloadLen <= 0 {
		payloadLen = connectudp.DefaultBenchUDPPayloadLen
	}
	sinkConn, seqSink := runUDPSequencedSink(tb, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0}, runID)
	sinkAddr := sinkConn.LocalAddr().(*net.UDPAddr)
	proxyPort := startInProcessMasqueUDPProxy(tb, func(mux *http.ServeMux, proxyPort int) {
		registerMasqueUDPProxyHandler(tb, mux, proxyPort)
	})
	target := net.JoinHostPort(sinkAddr.IP.String(), strconv.Itoa(sinkAddr.Port))
	pkt := dialH3ConnectUDPDirect(tb, proxyPort, target)
	return benchConnectUDPPacketUploadSequenced(tb, pkt, sinkAddr, seqSink, runID, duration, 0, payloadLen, true)
}

