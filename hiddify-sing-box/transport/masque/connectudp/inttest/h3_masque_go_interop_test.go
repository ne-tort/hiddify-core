package inttest_test

import (
	"bytes"
	"net"
	"net/http"
	"runtime"
	"strings"
	"testing"
	"time"

	masque "github.com/sagernet/sing-box/transport/masque"
	"github.com/sagernet/sing-box/transport/masque/connectudp/probe"
)

// Wave 3 interop matrix: masque-go Client.DialAddr (R1 fork via go.mod replace) → in-proc relay.Proxy.

func TestInteropMasqueGoClientEchoInProcess(t *testing.T) {
	echoAddr := masque.InttestRunUDPEcho(t)
	proxyPort := masque.InttestStartMasqueUDPProxyWithRelay(t)
	client, ctx := masque.InttestNewMasqueGoUDPClient(t)
	tmpl := masque.InttestMasqueGoUDPProxyTemplate(t, proxyPort)
	pkt, resp := masque.InttestMasqueGoDialUDP(t, client, ctx, tmpl, echoAddr)

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("CONNECT-UDP status: got %d want 200", resp.StatusCode)
	}
	if ps := resp.Header.Get("Proxy-Status"); ps == "" {
		t.Fatal("missing Proxy-Status next-hop on 2xx")
	}
	if !strings.Contains(resp.Header.Get("Proxy-Status"), "next-hop") {
		t.Fatalf("Proxy-Status: %q want next-hop", resp.Header.Get("Proxy-Status"))
	}

	payload := []byte("masque-go-interop-echo")
	deadline := time.Now().Add(3 * time.Second)
	if err := pkt.SetDeadline(deadline); err != nil {
		t.Fatalf("set deadline: %v", err)
	}
	if _, err := pkt.WriteTo(payload, echoAddr); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, 2048)
	n, addr, err := pkt.ReadFrom(buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(buf[:n]) != string(payload) {
		t.Fatalf("echo mismatch: got %q want %q", buf[:n], payload)
	}
	if !inttestUDPTargetAddrEqual(addr, echoAddr) {
		t.Fatalf("unexpected source addr %v want %v", addr, echoAddr)
	}
}

func TestInteropMasqueGoClientSplitPayloadEchoInProcess(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("H3 multi-datagram echo reassembly order unreliable on Windows loopback")
	}
	echoAddr := masque.InttestRunUDPEcho(t)
	proxyPort := masque.InttestStartMasqueUDPProxyWithRelay(t)
	client, ctx := masque.InttestNewMasqueGoUDPClient(t)
	tmpl := masque.InttestMasqueGoUDPProxyTemplate(t, proxyPort)
	pkt, _ := masque.InttestMasqueGoDialUDP(t, client, ctx, tmpl, echoAddr)

	wantLen := 2500
	payload := make([]byte, wantLen)
	for i := range payload {
		payload[i] = byte(i % 251)
	}
	deadline := time.Now().Add(4 * time.Second)
	if err := pkt.SetDeadline(deadline); err != nil {
		t.Fatalf("set deadline: %v", err)
	}
	nWr, err := pkt.WriteTo(payload, echoAddr)
	if err != nil {
		t.Fatalf("write: %v", err)
	}
	if nWr != wantLen {
		t.Fatalf("short write: %d want %d", nWr, wantLen)
	}

	got := make([]byte, 0, wantLen)
	buf := make([]byte, 2048)
	for len(got) < wantLen {
		n, addr, err := pkt.ReadFrom(buf)
		if err != nil {
			t.Fatalf("read: %v (got %d bytes)", err, len(got))
		}
		if !inttestUDPTargetAddrEqual(addr, echoAddr) {
			t.Fatalf("unexpected source addr %v want %v", addr, echoAddr)
		}
		got = append(got, buf[:n]...)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("split echo mismatch (len got=%d want=%d)", len(got), wantLen)
	}
}

func TestInteropMasqueGoClientJumboEchoRFCInterop(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("jumbo datagram echo unreliable on Windows loopback")
	}
	echoAddr := masque.InttestRunUDPEcho(t)
	proxyPort := masque.InttestStartMasqueUDPProxyWithRelayRFCInterop(t)
	client, ctx := masque.InttestNewMasqueGoUDPClient(t)
	tmpl := masque.InttestMasqueGoUDPProxyTemplate(t, proxyPort)
	pkt, _ := masque.InttestMasqueGoDialUDP(t, client, ctx, tmpl, echoAddr)

	wantLen := 2000
	payload := make([]byte, wantLen)
	for i := range payload {
		payload[i] = byte(i & 0xff)
	}
	deadline := time.Now().Add(4 * time.Second)
	if err := pkt.SetDeadline(deadline); err != nil {
		t.Fatalf("set deadline: %v", err)
	}
	if _, err := pkt.WriteTo(payload, echoAddr); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, wantLen+64)
	n, _, err := pkt.ReadFrom(buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if n != wantLen || !bytes.Equal(buf[:n], payload) {
		t.Fatalf("jumbo echo mismatch: got %d bytes", n)
	}
}

func TestInteropMasqueGoClientProdDropsJumbo(t *testing.T) {
	echoAddr := masque.InttestRunUDPEcho(t)
	proxyPort := masque.InttestStartMasqueUDPProxyWithRelay(t)
	client, ctx := masque.InttestNewMasqueGoUDPClient(t)
	tmpl := masque.InttestMasqueGoUDPProxyTemplate(t, proxyPort)
	pkt, _ := masque.InttestMasqueGoDialUDP(t, client, ctx, tmpl, echoAddr)

	payload := make([]byte, 2000)
	deadline := time.Now().Add(300 * time.Millisecond)
	if err := pkt.SetReadDeadline(deadline); err != nil {
		t.Fatalf("set read deadline: %v", err)
	}
	_, werr := pkt.WriteTo(payload, echoAddr)
	if werr != nil {
		// Prod masque-go client may reject jumbo before wire (QUIC DATAGRAM max).
		if strings.Contains(werr.Error(), "DATAGRAM frame too large") {
			return
		}
		t.Fatalf("write: %v", werr)
	}
	buf := make([]byte, 2048)
	_, _, err := pkt.ReadFrom(buf)
	if err == nil {
		t.Fatal("expected no echo in prod relay mode for 2000 B payload")
	}
	if ne, ok := err.(net.Error); !ok || !ne.Timeout() {
		t.Fatalf("read: %v want timeout", err)
	}
}

func TestInteropMasqueGoClientSequencedEchoInProcess(t *testing.T) {
	const (
		runID = uint32(0x1a2b3c4d)
		plen  = 512
		sent  = 16
	)
	echoAddr := masque.InttestRunUDPEcho(t)
	proxyPort := masque.InttestStartMasqueUDPProxyWithRelay(t)
	client, ctx := masque.InttestNewMasqueGoUDPClient(t)
	tmpl := masque.InttestMasqueGoUDPProxyTemplate(t, proxyPort)
	pkt, _ := masque.InttestMasqueGoDialUDP(t, client, ctx, tmpl, echoAddr)

	sink := probe.NewSequencedSink(runID)
	for i := range sent {
		p := probe.BuildProbePayload(uint64(i), runID, plen)
		if err := pkt.SetWriteDeadline(time.Now().Add(2 * time.Second)); err != nil {
			t.Fatalf("set write deadline seq %d: %v", i, err)
		}
		if _, err := pkt.WriteTo(p, echoAddr); err != nil {
			t.Fatalf("write seq %d: %v", i, err)
		}
		if err := pkt.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
			t.Fatalf("set read deadline seq %d: %v", i, err)
		}
		buf := make([]byte, plen+64)
		n, _, err := pkt.ReadFrom(buf)
		if err != nil {
			t.Fatalf("read seq %d: %v", i, err)
		}
		sink.Record(buf[:n])
	}
	st := sink.Analyze(sent, plen)
	if st.RxPkts != sent || st.LossPct != 0 {
		t.Fatalf("sequenced round-trip: %+v", st)
	}
}
