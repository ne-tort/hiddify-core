//go:build masque_ref

package masque

// R1 masque-go (third_party fork Proxy) reference benches — require -tags masque_ref.

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"testing"
	"time"

	qmasque "github.com/quic-go/masque-go"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/transport/masque/connectudp"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/yosida95/uritemplate/v3"
)

// registerMasqueGoRefUDPProxyHandler wires third_party masque-go Proxy (per-packet SendDatagram S2C).
func registerMasqueGoRefUDPProxyHandler(t testing.TB, mux *http.ServeMux, proxyPort int) {
	t.Helper()
	templateRaw := fmt.Sprintf("https://127.0.0.1:%d/masque/udp/{target_host}/{target_port}", proxyPort)
	udpTemplate, err := uritemplate.New(templateRaw)
	if err != nil {
		t.Fatalf("udp template: %v", err)
	}
	var udpProxy qmasque.Proxy
	t.Cleanup(func() { _ = udpProxy.Close() })
	mux.HandleFunc("/masque/udp/{target_host}/{target_port}", func(w http.ResponseWriter, r *http.Request) {
		req, err := qmasque.ParseRequest(r, udpTemplate)
		if err != nil {
			if pe, ok := err.(*qmasque.RequestParseError); ok {
				w.WriteHeader(pe.HTTPStatus)
				return
			}
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if err := udpProxy.Proxy(w, req); err != nil {
			w.WriteHeader(http.StatusBadGateway)
		}
	})
}

type connectUDPH3FountainBenchRow struct {
	label    string
	register func(testing.TB, *http.ServeMux, int)
}

// TestBenchConnectUDPH3FountainMasqueGoRefMatrix compares our connectudp/relay vs third_party masque-go Proxy (R1).
func TestBenchConnectUDPH3FountainMasqueGoRefMatrix(t *testing.T) {
	dur := connectUDPSynthProdBenchDuration
	payload := connectudp.DefaultBenchUDPPayloadLen

	rows := []connectUDPH3FountainBenchRow{
		{label: "ref-masque-go", register: registerMasqueGoRefUDPProxyHandler},
		{label: "ours-relay", register: registerMasqueUDPProxyHandler},
	}

	refMbps := 0.0
	oursMbps := 0.0

	for _, row := range rows {
		row := row
		t.Run(row.label, func(t *testing.T) {
			bytes, mbps, err := benchConnectUDPH3DirectDownloadFountainWithProxy(t, row.register, dur, payload)
			if err != nil {
				t.Fatalf("%s fountain: %v", row.label, err)
			}
			t.Logf("BENCH h3 fountain %s: %.1f Mbit/s (%d bytes)", row.label, mbps, bytes)
			switch row.label {
			case "ref-masque-go":
				refMbps = mbps
			case "ours-relay":
				oursMbps = mbps
			}
		})
	}

	if refMbps <= 0 {
		t.Fatal("ref masque-go baseline must be > 0 Mbit/s")
	}
	ratio := oursMbps / refMbps
	t.Logf("BENCH h3 fountain ours/ref ratio: %.2f (ours=%.1f ref=%.1f Mbit/s)", ratio, oursMbps, refMbps)
	const minOursRefRatio = 0.90
	if ratio < minOursRefRatio {
		t.Fatalf("ours/ref ratio %.2f < %.2f — relay regressed vs masque-go R1", ratio, minOursRefRatio)
	}
}

// TestBenchConnectUDPH3FountainMasqueGoRef is the single-run R1 baseline (~2s).
func TestBenchConnectUDPH3FountainMasqueGoRef(t *testing.T) {
	dur := connectUDPSynthProdBenchDuration
	_, mbps, err := benchConnectUDPH3DirectDownloadFountainWithProxy(
		t, registerMasqueGoRefUDPProxyHandler, dur, connectudp.DefaultBenchUDPPayloadLen,
	)
	if err != nil {
		t.Fatalf("masque-go ref fountain: %v", err)
	}
	t.Logf("BENCH h3 fountain ref-masque-go (R1): %.1f Mbit/s", mbps)
}

// TestBenchConnectUDPH3EchoRelayVsRef compares echo-duplex with our relay vs masque-go ref proxy.
func TestBenchConnectUDPH3EchoRelayVsRef(t *testing.T) {
	dur := connectUDPSynthProdBenchDuration
	runEcho := func(register func(testing.TB, *http.ServeMux, int)) float64 {
		echo := runUDPEcho(t, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
		echoAddr := echo.LocalAddr().(*net.UDPAddr)
		proxyPort := startInProcessMasqueUDPProxy(t, func(mux *http.ServeMux, proxyPort int) {
			register(t, mux, proxyPort)
		})
		waitCtx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		defer cancel()
		session, err := (CoreClientFactory{}).NewSession(waitCtx, ClientOptions{
			Server:              "127.0.0.1",
			ServerPort:          uint16(proxyPort),
			TransportMode:       option.MasqueTransportModeConnectUDP,
			MasqueQUICCryptoTLS: &tls.Config{InsecureSkipVerify: true},
		})
		if err != nil {
			t.Fatalf("session: %v", err)
		}
		defer func() { _ = session.Close() }()
		pkt, err := session.ListenPacket(waitCtx, M.Socksaddr{
			Addr: netip.MustParseAddr(echoAddr.IP.String()),
			Port: uint16(echoAddr.Port),
		})
		if err != nil {
			t.Fatalf("ListenPacket: %v", err)
		}
		defer func() { _ = pkt.Close() }()
		_, mbps, err := benchConnectUDPPacketDownloadViaEcho(t, pkt, echoAddr, dur, connectudp.DefaultBenchUDPPayloadLen)
		if err != nil {
			t.Fatalf("echo: %v", err)
		}
		return mbps
	}
	ours := runEcho(registerMasqueUDPProxyHandler)
	ref := runEcho(registerMasqueGoRefUDPProxyHandler)
	t.Logf("BENCH h3 echo ours-relay=%.1f ref-masque-go=%.1f ratio=%.2f", ours, ref, ours/ref)
}

// TestLocalizeConnectUDPH3FountainRelayVsRef compares our relay S2C path vs masque-go ref proxy.
func TestLocalizeConnectUDPH3FountainRelayVsRef(t *testing.T) {
	dur := connectUDPSynthProdBenchDuration
	_, ours, err := benchConnectUDPH3DirectDownloadFountainWithProxy(t, registerMasqueUDPProxyHandler, dur, connectudp.DefaultBenchUDPPayloadLen)
	if err != nil {
		t.Fatalf("ours fountain: %v", err)
	}
	_, ref, err := benchConnectUDPH3DirectDownloadFountainWithProxy(t, registerMasqueGoRefUDPProxyHandler, dur, connectudp.DefaultBenchUDPPayloadLen)
	if err != nil {
		t.Fatalf("ref fountain: %v", err)
	}
	t.Logf("LOCALIZE h3 fountain relay ours=%.1f ref=%.1f ratio=%.2f", ours, ref, ours/ref)
}
