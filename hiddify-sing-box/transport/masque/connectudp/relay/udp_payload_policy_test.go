package relay

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/quic-go/quic-go/quicvarint"
)

func TestRelayMaxUDPPayloadBytesProdDefault(t *testing.T) {
	t.Parallel()
	SetRelayPayloadPolicy(RelayPayloadProd)
	t.Cleanup(func() { SetRelayPayloadPolicy(RelayPayloadProd) })
	if got := RelayMaxUDPPayloadBytes(); got != ProdRelayMaxUDPPayloadBytes {
		t.Fatalf("cap: got %d want %d", got, ProdRelayMaxUDPPayloadBytes)
	}
	if !relayExceedsMTUCap(ProdRelayMaxUDPPayloadBytes + 1) {
		t.Fatal("expected prod cap exceed at 1501")
	}
}

func TestRelayMaxUDPPayloadBytesRFCInterop(t *testing.T) {
	SetRelayPayloadPolicy(RelayPayloadRFCInterop)
	t.Cleanup(func() { SetRelayPayloadPolicy(RelayPayloadProd) })
	if got := RelayMaxUDPPayloadBytes(); got != 65527 {
		t.Fatalf("cap: got %d want 65527", got)
	}
	if relayExceedsMTUCap(2000) {
		t.Fatal("2000 B should pass in RFC interop mode")
	}
}

func TestParseRelayPayloadPolicyConfig(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in   string
		want RelayPayloadPolicy
		err  bool
	}{
		{"", RelayPayloadProd, false},
		{"prod", RelayPayloadProd, false},
		{"PROD", RelayPayloadProd, false},
		{"rfc_interop", RelayPayloadRFCInterop, false},
		{"RFC_INTEROP", RelayPayloadRFCInterop, false},
		{"jumbo", RelayPayloadProd, true},
	}
	for _, tc := range cases {
		got, err := ParseRelayPayloadPolicyConfig(tc.in)
		if tc.err {
			if err == nil {
				t.Fatalf("ParseRelayPayloadPolicyConfig(%q): want error", tc.in)
			}
			continue
		}
		if err != nil {
			t.Fatalf("ParseRelayPayloadPolicyConfig(%q): %v", tc.in, err)
		}
		if got != tc.want {
			t.Fatalf("ParseRelayPayloadPolicyConfig(%q): got %v want %v", tc.in, got, tc.want)
		}
	}
}

func TestConfigureRelayPayloadPolicyFromConfig(t *testing.T) {
	t.Cleanup(func() { SetRelayPayloadPolicy(RelayPayloadProd) })
	if err := ConfigureRelayPayloadPolicyFromConfig(RelayPayloadConfigRFCInterop); err != nil {
		t.Fatal(err)
	}
	if RelayPayloadPolicyCurrent() != RelayPayloadRFCInterop {
		t.Fatalf("policy: got %v want RFCInterop", RelayPayloadPolicyCurrent())
	}
}

type oneShotC2SStream struct {
	payload []byte
	sent    bool
}

func (s *oneShotC2SStream) ReceiveDatagram(context.Context) ([]byte, error) {
	if s.sent {
		return nil, io.EOF
	}
	s.sent = true
	return s.payload, nil
}

// TestProxyConnSendRFCInteropForwardsAboveProdMTU locks C2S relay pass-through for 2000 B when RFC interop policy is on.
func TestProxyConnSendRFCInteropForwardsAboveProdMTU(t *testing.T) {
	SetRelayPayloadPolicy(RelayPayloadRFCInterop)
	t.Cleanup(func() { SetRelayPayloadPolicy(RelayPayloadProd) })

	srv, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	conn, err := net.DialUDP("udp", nil, srv.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	udpPayload := make([]byte, 2000)
	for i := range udpPayload {
		udpPayload[i] = byte(i)
	}
	dgram := append(quicvarint.Append([]byte{}, 0), udpPayload...)
	str := &oneShotC2SStream{payload: dgram}

	done := make(chan error, 1)
	go func() {
		done <- (&Proxy{}).proxyConnSend(context.Background(), conn, str)
	}()

	buf := make([]byte, 4096)
	n, _, err := srv.ReadFromUDP(buf)
	if err != nil {
		t.Fatal(err)
	}
	if n != len(udpPayload) {
		t.Fatalf("rx len: got %d want %d", n, len(udpPayload))
	}
	if err := <-done; err != nil {
		t.Fatalf("proxyConnSend: %v", err)
	}
}

// TestProxyConnSendProdDropsAboveMTU locks prod silent drop for payloads >1500 B.
func TestProxyConnSendProdDropsAboveMTU(t *testing.T) {
	SetRelayPayloadPolicy(RelayPayloadProd)
	t.Cleanup(func() { SetRelayPayloadPolicy(RelayPayloadProd) })

	srv, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	conn, err := net.DialUDP("udp", nil, srv.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	udpPayload := make([]byte, 2000)
	dgram := append(quicvarint.Append([]byte{}, 0), udpPayload...)
	str := &oneShotC2SStream{payload: dgram}

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	_ = (&Proxy{}).proxyConnSend(ctx, conn, str)

	srv.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
	buf := make([]byte, 4096)
	_, _, err = srv.ReadFromUDP(buf)
	if err == nil {
		t.Fatal("expected no datagram in prod mode for 2000 B payload")
	}
}
