package masque

import (
	"errors"
	"testing"
	"time"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"
)

func TestValidateMasqueOptionsClientMinimal(t *testing.T) {
	opts := option.MasqueEndpointOptions{
		ServerOptions: option.ServerOptions{
			Server:     "masque.example",
			ServerPort: 443,
		},
		TransportMode: option.MasqueTransportModeConnectUDP,
		TCPTransport:  option.MasqueTCPTransportConnectStream,
	}
	if err := validateMasqueOptions(opts); err != nil {
		t.Fatalf("expected ok: %v", err)
	}
}

func TestValidateMasqueOptionsRejectsUdpTimeout(t *testing.T) {
	opts := option.MasqueEndpointOptions{
		ServerOptions: option.ServerOptions{Server: "x", ServerPort: 443},
		TCPTransport:  option.MasqueTCPTransportConnectStream,
	}
	opts.UDPTimeout = badoption.Duration(5 * time.Second)
	if err := validateMasqueOptions(opts); err == nil {
		t.Fatal("expected error for udp_timeout")
	}
}

func TestValidateMasqueConnectUDPIPIllegal(t *testing.T) {
	opts := option.MasqueEndpointOptions{
		ServerOptions: option.ServerOptions{Server: "x", ServerPort: 443},
		TransportMode: option.MasqueTransportModeConnectUDP,
		TCPTransport:  option.MasqueTCPTransportConnectStream,
		TemplateIP:    "https://x/ip",
	}
	if err := validateMasqueOptions(opts); err == nil {
		t.Fatal("expected error for template_ip with connect_udp")
	}
}

func TestValidateMasqueOptionsHopsRequiresChain(t *testing.T) {
	opts := option.MasqueEndpointOptions{
		ServerOptions: option.ServerOptions{Server: "x", ServerPort: 443},
		TCPTransport:  option.MasqueTCPTransportConnectStream,
		HopPolicy:     option.MasqueHopPolicySingle,
		Hops: []option.MasqueChainHopOptions{
			{Tag: "a", ServerOptions: option.ServerOptions{Server: "relay.example", ServerPort: 443}},
		},
	}
	if err := validateMasqueOptions(opts); err == nil {
		t.Fatal("expected error: hops without hop_policy chain")
	}
}

func TestValidateWarpMasqueConsumerRequiresPairedTokenAndID(t *testing.T) {
	noID := option.WarpMasqueEndpointOptions{
		MasqueEndpointOptions: option.MasqueEndpointOptions{
			ServerOptions: option.ServerOptions{Server: "bootstrap.warp.invalid", ServerPort: 443},
			TCPTransport:  option.MasqueTCPTransportConnectStream,
		},
		Profile: option.WarpMasqueProfileOptions{
			Compatibility: option.WarpMasqueCompatibilityConsumer,
			AuthToken:     "x",
		},
	}
	if err := validateWarpMasqueOptions(noID); err == nil {
		t.Fatal("expected error: token without id")
	}
	noTok := option.WarpMasqueEndpointOptions{
		MasqueEndpointOptions: option.MasqueEndpointOptions{
			ServerOptions: option.ServerOptions{Server: "bootstrap.warp.invalid", ServerPort: 443},
			TCPTransport:  option.MasqueTCPTransportConnectStream,
		},
		Profile: option.WarpMasqueProfileOptions{
			Compatibility: option.WarpMasqueCompatibilityConsumer,
			ID:            "device-uuid",
		},
	}
	if err := validateWarpMasqueOptions(noTok); err == nil {
		t.Fatal("expected error: id without token")
	}
	ok := option.WarpMasqueEndpointOptions{
		MasqueEndpointOptions: option.MasqueEndpointOptions{
			ServerOptions: option.ServerOptions{Server: "bootstrap.warp.invalid", ServerPort: 443},
			TCPTransport:  option.MasqueTCPTransportConnectStream,
		},
		Profile: option.WarpMasqueProfileOptions{
			Compatibility: option.WarpMasqueCompatibilityConsumer,
			AuthToken:     "tok",
			ID:            "id",
		},
	}
	if err := validateWarpMasqueOptions(ok); err != nil {
		t.Fatalf("expected ok when token+id paired: %v", err)
	}
}

func TestClassifyMasqueFailure(t *testing.T) {
	if g, w := ClassifyMasqueFailure(errors.New("connect-ip: server didn't enable Extended CONNECT")), "h3_extended_connect"; g != w {
		t.Fatalf("got %q want %q", g, w)
	}
}

func TestValidateWarpMasqueRejectInvalidDataplanePortStrategy(t *testing.T) {
	opts := option.WarpMasqueEndpointOptions{
		MasqueEndpointOptions: option.MasqueEndpointOptions{
			ServerOptions: option.ServerOptions{Server: "bootstrap.warp.invalid", ServerPort: 443},
			TCPTransport:  option.MasqueTCPTransportConnectStream,
		},
		Profile: option.WarpMasqueProfileOptions{
			Compatibility:         option.WarpMasqueCompatibilityConsumer,
			DataplanePortStrategy: "invalid_strategy",
		},
	}
	if err := validateWarpMasqueOptions(opts); err == nil {
		t.Fatal("expected error")
	}
}

func TestIsRetryableWarpMasqueDataplanePortIdleTimeout(t *testing.T) {
	if !IsRetryableWarpMasqueDataplanePort(errors.New("timeout: no recent network activity")) {
		t.Fatal("expected retryable for QUIC idle-style errors")
	}
	if IsRetryableWarpMasqueDataplanePort(errors.New("401 Unauthorized")) {
		t.Fatal("auth must not rotate ports")
	}
}
