package session

import (
	"testing"

	"github.com/sagernet/sing-box/option"
)

func TestIsTCPNetwork(t *testing.T) {
	if !IsTCPNetwork("tcp") || !IsTCPNetwork("TCP4") || !IsTCPNetwork(" tcp6 ") {
		t.Fatal("expected tcp family accepted")
	}
	if IsTCPNetwork("udp") {
		t.Fatal("udp must be rejected")
	}
}

func TestNormalizeTCPTransport(t *testing.T) {
	if got := NormalizeTCPTransport(option.MasqueTCPTransportConnectStream); got != option.MasqueTCPTransportConnectStream {
		t.Fatalf("connect_stream: got %q", got)
	}
	if got := NormalizeTCPTransport(""); got != option.MasqueTCPTransportAuto {
		t.Fatalf("empty: got %q", got)
	}
}

func TestTCPMasqueDirectFallbackEnabled(t *testing.T) {
	on := ClientOptions{
		TCPMode:        option.MasqueTCPModeMasqueOrDirect,
		FallbackPolicy: option.MasqueFallbackPolicyDirectExplicit,
	}
	if !TCPMasqueDirectFallbackEnabled(on) {
		t.Fatal("expected enabled")
	}
	off := ClientOptions{TCPMode: option.MasqueTCPModeStrictMasque}
	if TCPMasqueDirectFallbackEnabled(off) {
		t.Fatal("expected disabled")
	}
}
