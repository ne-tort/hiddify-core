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

func TestDataplaneUsesConnectIP(t *testing.T) {
	if DataplaneUsesConnectIP(option.MasqueDataplaneConnectIP) != true {
		t.Fatal("connect_ip dataplane")
	}
	if DataplaneUsesConnectIP(option.MasqueDataplaneDefault) {
		t.Fatal("default must not use connect_ip plane")
	}
	if DataplaneUsesConnectIP("") {
		t.Fatal("empty must not use connect_ip plane")
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
