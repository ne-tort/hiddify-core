//go:build masque_ref

package masque

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/netip"
	"testing"
	"time"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/transport/masque/connectudp"
	M "github.com/sagernet/sing/common/metadata"
)

func InttestBenchConnectUDPH3FountainMasqueGoRefMatrix(t *testing.T) {
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

func InttestBenchConnectUDPH3FountainMasqueGoRef(t *testing.T) {
	dur := connectUDPSynthProdBenchDuration
	_, mbps, err := benchConnectUDPH3DirectDownloadFountainWithProxy(
		t, registerMasqueGoRefUDPProxyHandler, dur, connectudp.DefaultBenchUDPPayloadLen,
	)
	if err != nil {
		t.Fatalf("masque-go ref fountain: %v", err)
	}
	t.Logf("BENCH h3 fountain ref-masque-go (R1): %.1f Mbit/s", mbps)
}

func InttestBenchConnectUDPH3EchoRelayVsRef(t *testing.T) {
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

func InttestLocalizeConnectUDPH3FountainRelayVsRef(t *testing.T) {
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
