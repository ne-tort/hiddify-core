package config

import (
	"context"
	"encoding/json"
	"testing"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/experimental/libbox"
)

func TestBuildConfigMinimalMasqueEndpointPassthrough(t *testing.T) {
	const input = `{
  "endpoints": [
    {
      "type": "masque",
      "tag": "masque-min",
      "server": "example.com",
      "server_port": 443,
      "insecure": true
    }
  ]
}`

	ctx := libbox.BaseContext(nil)
	options, err := ReadSingOptions(ctx, &ReadOptions{Content: input})
	if err != nil {
		t.Fatal(err)
	}
	built, err := BuildConfig(ctx, DefaultHiddifyOptions(), &ReadOptions{Options: options})
	if err != nil {
		t.Fatal(err)
	}
	if len(built.Endpoints) != 1 {
		t.Fatalf("expected one endpoint, got %d", len(built.Endpoints))
	}
	endpoint := marshalSingleEndpoint(t, ctx, built)
	if endpoint["type"] != "masque" {
		t.Fatalf("expected masque, got %v", endpoint["type"])
	}
	if endpoint["server"] != "example.com" {
		t.Fatalf("server: %v", endpoint["server"])
	}
}

func TestBuildConfigPassthroughMasqueConnectUDPWithTemplateIP(t *testing.T) {
	const input = `{
  "endpoints": [
    {
      "type": "masque",
      "tag": "masque-raw",
      "server": "example.com",
      "server_port": 443,
      "transport_mode": "connect_udp",
      "tcp_transport": "connect_stream",
      "template_ip": "https://example.com:443/masque/ip",
      "insecure": true
    }
  ]
}`

	ctx := libbox.BaseContext(nil)
	options, err := ReadSingOptions(ctx, &ReadOptions{Content: input})
	if err != nil {
		t.Fatal(err)
	}
	built, err := BuildConfig(ctx, DefaultHiddifyOptions(), &ReadOptions{Options: options})
	if err != nil {
		t.Fatal(err)
	}
	endpoint := marshalSingleEndpoint(t, ctx, built)
	if endpoint["template_ip"] != "https://example.com:443/masque/ip" {
		t.Fatalf("Hiddify BuildConfig must not strip template_ip (runtime NewEndpoint sanitizes): %v", endpoint["template_ip"])
	}
}

func TestBuildConfigPreservesMasqueEndpoint(t *testing.T) {
	const input = `{
  "endpoints": [
    {
      "type": "masque",
      "tag": "masque-client",
      "server": "example.com",
      "server_port": 443,
      "transport_mode": "connect_ip",
      "fallback_policy": "strict",
      "tcp_mode": "strict_masque",
      "tcp_transport": "connect_stream",
      "template_ip": "https://example.com:443/masque/ip",
      "template_tcp": "https://example.com:443/masque/tcp/{target_host}/{target_port}",
      "tls_server_name": "example.com"
    }
  ]
}`

	ctx := libbox.BaseContext(nil)
	options, err := ReadSingOptions(ctx, &ReadOptions{Content: input})
	if err != nil {
		t.Fatal(err)
	}
	built, err := BuildConfig(ctx, DefaultHiddifyOptions(), &ReadOptions{Options: options})
	if err != nil {
		t.Fatal(err)
	}
	if len(built.Endpoints) != 1 {
		t.Fatalf("expected one endpoint, got %d", len(built.Endpoints))
	}
	if got := built.Endpoints[0].Type; got != "masque" {
		t.Fatalf("expected masque endpoint type, got %q", got)
	}

	endpoint := marshalSingleEndpoint(t, ctx, built)
	if endpoint["template_ip"] != "https://example.com:443/masque/ip" {
		t.Fatalf("template_ip was not preserved: %v", endpoint["template_ip"])
	}
	if endpoint["tcp_transport"] != "connect_stream" {
		t.Fatalf("tcp_transport was not preserved: %v", endpoint["tcp_transport"])
	}
}

func TestBuildConfigPreservesWarpMasqueEndpoint(t *testing.T) {
	const input = `{
  "endpoints": [
    {
      "type": "warp_masque",
      "tag": "warp-masque-client",
      "transport_mode": "connect_ip",
      "tcp_transport": "connect_stream",
      "http_layer": "h2",
      "http_layer_fallback": false,
      "profile": {
        "id": "test-device",
        "auth_token": "test-auth-token",
        "masque_ecdsa_private_key": "test-ecdsa-key",
        "auto_enroll_masque": false
      }
    }
  ]
}`

	ctx := libbox.BaseContext(nil)
	options, err := ReadSingOptions(ctx, &ReadOptions{Content: input})
	if err != nil {
		t.Fatal(err)
	}
	built, err := BuildConfig(ctx, DefaultHiddifyOptions(), &ReadOptions{Options: options})
	if err != nil {
		t.Fatal(err)
	}
	if len(built.Endpoints) != 1 {
		t.Fatalf("expected one endpoint, got %d", len(built.Endpoints))
	}
	if got := built.Endpoints[0].Type; got != "warp_masque" {
		t.Fatalf("expected warp_masque endpoint type, got %q", got)
	}

	endpoint := marshalSingleEndpoint(t, ctx, built)
	if endpoint["http_layer"] != "h2" {
		t.Fatalf("http_layer was not preserved: %v", endpoint["http_layer"])
	}
	profile, ok := endpoint["profile"].(map[string]any)
	if !ok {
		t.Fatalf("expected profile object, got %#v", endpoint["profile"])
	}
	if profile["auth_token"] != "test-auth-token" {
		t.Fatalf("profile.auth_token was not preserved: %v", profile["auth_token"])
	}
	if profile["masque_ecdsa_private_key"] != "test-ecdsa-key" {
		t.Fatalf("profile.masque_ecdsa_private_key was not preserved: %v", profile["masque_ecdsa_private_key"])
	}
}

func TestBuildConfigMasqueDoesNotInjectTunServerIPBypassRule(t *testing.T) {
	const input = `{
  "endpoints": [
    {
      "type": "masque",
      "tag": "masque-lab",
      "server": "203.0.113.5",
      "server_port": 8443,
      "insecure": true
    }
  ]
}`

	ctx := libbox.BaseContext(nil)
	options, err := ReadSingOptions(ctx, &ReadOptions{Content: input})
	if err != nil {
		t.Fatal(err)
	}
	built, err := BuildConfig(ctx, DefaultHiddifyOptions(), &ReadOptions{Options: options})
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range built.Route.Rules {
		if r.Type != C.RuleTypeDefault {
			continue
		}
		d := r.DefaultOptions.RawDefaultRule
		if len(d.Inbound) != 1 || d.Inbound[0] != InboundTUNTag {
			continue
		}
		for _, cidr := range d.IPCIDR {
			if cidr == "203.0.113.5/32" &&
				r.DefaultOptions.RouteOptions.Outbound == OutboundDirectTag {
				t.Fatal("unexpected tun-in + MASQUE server /32 -> direct rule; bootstrap must use sing-box dialer protections instead")
			}
		}
	}
}

func marshalSingleEndpoint(t *testing.T, ctx context.Context, options interface {
	MarshalJSONContext(context.Context) ([]byte, error)
}) map[string]any {
	t.Helper()
	raw, err := options.MarshalJSONContext(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var root map[string]any
	if err := json.Unmarshal(raw, &root); err != nil {
		t.Fatal(err)
	}
	endpoints, ok := root["endpoints"].([]any)
	if !ok || len(endpoints) != 1 {
		t.Fatalf("expected one endpoint in JSON, got %#v", root["endpoints"])
	}
	endpoint, ok := endpoints[0].(map[string]any)
	if !ok {
		t.Fatalf("expected endpoint object, got %#v", endpoints[0])
	}
	return endpoint
}
