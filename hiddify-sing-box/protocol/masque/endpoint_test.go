package masque

import (
	"context"
	"errors"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
	TM "github.com/sagernet/sing-box/transport/masque"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/yosida95/uritemplate/v3"
)

type testControlAdapter struct {
	server string
	port   uint16
	err    error
}

func TestWarpEndpointStartupErrorIsObservable(t *testing.T) {
	epRaw, err := NewWarpEndpoint(nil, nil, nil, "wm-fail", option.WarpMasqueEndpointOptions{
		MasqueEndpointOptions: option.MasqueEndpointOptions{
			HopPolicy:    option.MasqueHopPolicySingle,
			TCPTransport: option.MasqueTCPTransportConnectStream,
		},
	})
	if err != nil {
		t.Fatalf("new warp endpoint: %v", err)
	}
	ep := epRaw.(*WarpEndpoint)
	ep.controlAdapter = testControlAdapter{err: errors.New("bootstrap failed")}
	if err := ep.Start(adapter.StartStatePostStart); err != nil {
		t.Fatalf("start warp endpoint: %v", err)
	}
	time.Sleep(50 * time.Millisecond)
	_, err = ep.ListenPacket(context.Background(), M.Socksaddr{})
	if err == nil {
		t.Fatal("expected startup error to be returned")
	}
	if got := TM.ClassifyError(err); got != TM.ErrorClassTransport {
		t.Fatalf("expected startup error class transport_init, got %s (err=%v)", got, err)
	}
}

func TestWarpEndpointDependenciesIncludeProfileDetour(t *testing.T) {
	epRaw, err := NewWarpEndpoint(nil, nil, nil, "wm-deps", option.WarpMasqueEndpointOptions{
		MasqueEndpointOptions: option.MasqueEndpointOptions{
			DialerOptions: option.DialerOptions{Detour: "detour-a"},
			TCPTransport:  option.MasqueTCPTransportConnectStream,
		},
		Profile: option.WarpMasqueProfileOptions{Detour: "detour-b"},
	})
	if err != nil {
		t.Fatalf("new warp endpoint: %v", err)
	}
	ep := epRaw.(*WarpEndpoint)
	deps := ep.Dependencies()
	if len(deps) != 2 {
		t.Fatalf("expected 2 dependencies, got %d", len(deps))
	}
}

func TestWarpEndpointCompatibilityValidation(t *testing.T) {
	_, err := NewWarpEndpoint(nil, nil, nil, "wm-compat", option.WarpMasqueEndpointOptions{
		MasqueEndpointOptions: option.MasqueEndpointOptions{
			HopPolicy:    option.MasqueHopPolicySingle,
			TCPTransport: option.MasqueTCPTransportConnectStream,
		},
		Profile: option.WarpMasqueProfileOptions{
			Compatibility: option.WarpMasqueCompatibilityZeroTrust,
		},
	})
	if err == nil {
		t.Fatal("expected validation error for zero_trust compatibility without auth_token")
	}
	_, err = NewWarpEndpoint(nil, nil, nil, "wm-compat-2", option.WarpMasqueEndpointOptions{
		MasqueEndpointOptions: option.MasqueEndpointOptions{
			HopPolicy:    option.MasqueHopPolicySingle,
			TCPTransport: option.MasqueTCPTransportConnectStream,
		},
		Profile: option.WarpMasqueProfileOptions{
			Compatibility: option.WarpMasqueCompatibilityZeroTrust,
			AuthToken:     "token",
		},
	})
	if err == nil {
		t.Fatal("expected validation error for zero_trust compatibility without id")
	}
	_, err = NewWarpEndpoint(nil, nil, nil, "wm-compat-3", option.WarpMasqueEndpointOptions{
		MasqueEndpointOptions: option.MasqueEndpointOptions{
			HopPolicy:    option.MasqueHopPolicySingle,
			TCPTransport: option.MasqueTCPTransportConnectStream,
		},
		Profile: option.WarpMasqueProfileOptions{
			Compatibility: option.WarpMasqueCompatibilityConsumer,
			AuthToken:     "token",
		},
	})
	if err == nil {
		t.Fatal("expected consumer compatibility to reject auth_token")
	}
}

func (a testControlAdapter) ResolveServer(ctx context.Context, options option.WarpMasqueEndpointOptions) (string, uint16, error) {
	return a.server, a.port, a.err
}

func TestNewEndpointValidation(t *testing.T) {
	_, err := NewEndpoint(nil, nil, nil, "m1", option.MasqueEndpointOptions{
		HopPolicy: option.MasqueHopPolicySingle,
	})
	if err == nil {
		t.Fatal("expected validation error for missing server")
	}
	_, err = NewEndpoint(nil, nil, nil, "m1", option.MasqueEndpointOptions{
		ServerOptions: option.ServerOptions{Server: "example.com"},
		HopPolicy:     option.MasqueHopPolicyChain,
	})
	if err == nil {
		t.Fatal("expected validation error for chain without hops")
	}
}

func TestBuildQUICDialFuncAllowsEmptyDialerOptions(t *testing.T) {
	quicDial, err := buildQUICDialFunc(context.Background(), option.DialerOptions{}, true)
	if err != nil {
		t.Fatalf("expected empty dialer options to keep default QUIC dial path, got: %v", err)
	}
	if quicDial != nil {
		t.Fatal("expected empty dialer options to return nil QUIC dial override")
	}
}

func TestBuildQUICDialFuncRejectsInvalidNonEmptyDialerOptions(t *testing.T) {
	_, err := buildQUICDialFunc(context.Background(), option.DialerOptions{
		Detour: "missing-detour-tag",
	}, true)
	if err == nil {
		t.Fatal("expected invalid non-empty dialer options to fail fast")
	}
}

func TestEndpointReadinessAfterStart(t *testing.T) {
	epRaw, err := NewEndpoint(nil, nil, nil, "m1", option.MasqueEndpointOptions{
		ServerOptions: option.ServerOptions{Server: "example.com"},
		HopPolicy:     option.MasqueHopPolicySingle,
		TCPTransport:  option.MasqueTCPTransportConnectStream,
	})
	if err != nil {
		t.Fatalf("new endpoint: %v", err)
	}
	ep := epRaw.(*Endpoint)
	if ep.IsReady() {
		t.Fatal("endpoint must not be ready before Start")
	}
	if err := ep.Start(adapter.StartStatePostStart); err != nil {
		t.Fatalf("start endpoint: %v", err)
	}
	if !ep.IsReady() {
		t.Fatal("endpoint must be ready after successful Start")
	}
}

func TestWarpEndpointParityBootstrapHook(t *testing.T) {
	epRaw, err := NewWarpEndpoint(nil, nil, nil, "wm1", option.WarpMasqueEndpointOptions{
		MasqueEndpointOptions: option.MasqueEndpointOptions{
			HopPolicy:    option.MasqueHopPolicySingle,
			TCPTransport: option.MasqueTCPTransportConnectStream,
		},
	})
	if err != nil {
		t.Fatalf("new warp endpoint: %v", err)
	}
	ep := epRaw.(*WarpEndpoint)
	ep.controlAdapter = testControlAdapter{server: "engage.cloudflareclient.com", port: 443}
	if err := ep.Start(adapter.StartStatePostStart); err != nil {
		t.Fatalf("start warp endpoint: %v", err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for !ep.IsReady() && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if !ep.IsReady() {
		t.Fatal("warp endpoint must be ready after bootstrap and runtime start")
	}
}

func TestNewEndpointRejectInvalidChainVia(t *testing.T) {
	_, err := NewEndpoint(nil, nil, nil, "m2", option.MasqueEndpointOptions{
		HopPolicy: option.MasqueHopPolicyChain,
		Hops: []option.MasqueChainHopOptions{
			{Tag: "a", Via: "ghost", ServerOptions: option.ServerOptions{Server: "a.example", ServerPort: 443}},
		},
	})
	if err == nil {
		t.Fatal("expected invalid via validation error")
	}
}

func TestEndpointTransportModes(t *testing.T) {
	modes := []string{
		option.MasqueTransportModeAuto,
		option.MasqueTransportModeConnectUDP,
		option.MasqueTransportModeConnectIP,
	}
	for _, mode := range modes {
		epRaw, err := NewEndpoint(nil, nil, nil, "mode-"+mode, option.MasqueEndpointOptions{
			ServerOptions: option.ServerOptions{Server: "example.com", ServerPort: 443},
			HopPolicy:     option.MasqueHopPolicySingle,
			TransportMode: mode,
			TCPTransport:  option.MasqueTCPTransportConnectStream,
		})
		if err != nil {
			t.Fatalf("new endpoint for mode %s: %v", mode, err)
		}
		ep := epRaw.(*Endpoint)
		if mode == option.MasqueTransportModeConnectIP {
			// connect_ip now eagerly initializes IP-plane at Start and requires
			// a reachable MASQUE CONNECT-IP server; this unit test only validates
			// option wiring and mode acceptance.
			continue
		}
		if err := ep.Start(adapter.StartStatePostStart); err != nil {
			t.Fatalf("start endpoint for mode %s: %v", mode, err)
		}
	}
}

func TestServerModeValidation(t *testing.T) {
	_, err := NewEndpoint(nil, nil, nil, "srv1", option.MasqueEndpointOptions{
		Mode: option.MasqueModeServer,
	})
	if err == nil {
		t.Fatal("expected validation error for missing listen/certificate in server mode")
	}
	epRaw, err := NewEndpoint(nil, nil, nil, "srv2", option.MasqueEndpointOptions{
		Mode:        option.MasqueModeServer,
		Listen:      "127.0.0.1",
		ListenPort:  8443,
		Certificate: "cert.pem",
		Key:         "key.pem",
	})
	if err != nil {
		t.Fatalf("new server mode endpoint: %v", err)
	}
	if _, ok := epRaw.(*ServerEndpoint); !ok {
		t.Fatal("expected server endpoint implementation in server mode")
	}
	_, err = NewEndpoint(nil, nil, nil, "srv3", option.MasqueEndpointOptions{
		Mode:          option.MasqueModeServer,
		Listen:        "127.0.0.1",
		ListenPort:    8443,
		Certificate:   "cert.pem",
		Key:           "key.pem",
		TransportMode: option.MasqueTransportModeConnectUDP,
	})
	if err == nil {
		t.Fatal("expected server mode to reject client transport fields")
	}
	_, err = NewEndpoint(nil, nil, nil, "srv4", option.MasqueEndpointOptions{
		Mode:        option.MasqueModeServer,
		Listen:      "127.0.0.1",
		ListenPort:  8443,
		Certificate: "cert.pem",
		Key:         "key.pem",
		TemplateTCP: "https://masque.local/masque/tcp",
	})
	if err == nil {
		t.Fatal("expected server mode template_tcp placeholder validation error")
	}
}

func TestEndpointServerModeRejectsConnectIPScopeFields(t *testing.T) {
	_, err := NewEndpoint(nil, nil, nil, "server-reject-scope", option.MasqueEndpointOptions{
		Mode:                 option.MasqueModeServer,
		Listen:               "127.0.0.1",
		ListenPort:           8443,
		Certificate:          "cert.pem",
		Key:                  "key.pem",
		ConnectIPScopeTarget: "10.0.0.0/8",
	})
	if err == nil {
		t.Fatal("expected server mode to reject connect_ip_scope_* client-only fields")
	}
}

func TestEndpointTCPModeValidation(t *testing.T) {
	_, err := NewEndpoint(nil, nil, nil, "tcp-invalid", option.MasqueEndpointOptions{
		ServerOptions:  option.ServerOptions{Server: "example.com", ServerPort: 443},
		HopPolicy:      option.MasqueHopPolicySingle,
		TCPMode:        option.MasqueTCPModeMasqueOrDirect,
		FallbackPolicy: option.MasqueFallbackPolicyStrict,
	})
	if err == nil {
		t.Fatal("expected validation error for tcp_mode=masque_or_direct without direct_explicit fallback")
	}
}

func TestEndpointRejectsInvalidMTU(t *testing.T) {
	_, err := NewEndpoint(nil, nil, nil, "unsupported-tunables", option.MasqueEndpointOptions{
		ServerOptions: option.ServerOptions{Server: "example.com", ServerPort: 443},
		HopPolicy:     option.MasqueHopPolicySingle,
		MTU:           1200,
	})
	if err == nil {
		t.Fatal("expected validation error for invalid mtu range")
	}
}

func TestEndpointRejectsInvalidRawEnums(t *testing.T) {
	_, err := NewEndpoint(nil, nil, nil, "invalid-raw", option.MasqueEndpointOptions{
		ServerOptions:  option.ServerOptions{Server: "example.com", ServerPort: 443},
		HopPolicy:      option.MasqueHopPolicySingle,
		TransportMode:  "bad_mode",
		FallbackPolicy: option.MasqueFallbackPolicyStrict,
	})
	if err == nil {
		t.Fatal("expected invalid transport_mode error")
	}
}

func TestEndpointRejectsInvalidRawTCPAndFallbackEnums(t *testing.T) {
	testCases := []struct {
		name string
		opts option.MasqueEndpointOptions
	}{
		{
			name: "invalid tcp_mode",
			opts: option.MasqueEndpointOptions{
				ServerOptions: option.ServerOptions{Server: "example.com", ServerPort: 443},
				HopPolicy:     option.MasqueHopPolicySingle,
				TCPMode:       "bad_mode",
				TCPTransport:  option.MasqueTCPTransportConnectStream,
			},
		},
		{
			name: "invalid fallback_policy",
			opts: option.MasqueEndpointOptions{
				ServerOptions:  option.ServerOptions{Server: "example.com", ServerPort: 443},
				HopPolicy:      option.MasqueHopPolicySingle,
				TCPTransport:   option.MasqueTCPTransportConnectStream,
				FallbackPolicy: "bad_fallback",
			},
		},
		{
			name: "invalid tcp_transport",
			opts: option.MasqueEndpointOptions{
				ServerOptions: option.ServerOptions{Server: "example.com", ServerPort: 443},
				HopPolicy:     option.MasqueHopPolicySingle,
				TCPTransport:  "bad_transport",
			},
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewEndpoint(nil, nil, nil, "invalid-raw-"+tc.name, tc.opts)
			if err == nil {
				t.Fatalf("expected validation error for %s", tc.name)
			}
		})
	}
}

func TestEndpointWhitespaceRawEnumsUseDefaults(t *testing.T) {
	_, err := NewEndpoint(nil, nil, nil, "raw-whitespace-defaults", option.MasqueEndpointOptions{
		Mode:           "   ",
		ServerOptions:  option.ServerOptions{Server: "example.com", ServerPort: 443},
		HopPolicy:      option.MasqueHopPolicySingle,
		TransportMode:  "   ",
		FallbackPolicy: "   ",
		TCPMode:        "   ",
		TCPTransport:   option.MasqueTCPTransportConnectStream,
	})
	if err != nil {
		t.Fatalf("expected whitespace raw enums to normalize to defaults, got %v", err)
	}
}

func TestEndpointRejectsInvalidModeEnum(t *testing.T) {
	_, err := NewEndpoint(nil, nil, nil, "invalid-mode", option.MasqueEndpointOptions{
		Mode:          "bad_mode",
		ServerOptions: option.ServerOptions{Server: "example.com", ServerPort: 443},
		HopPolicy:     option.MasqueHopPolicySingle,
		TCPTransport:  option.MasqueTCPTransportConnectStream,
	})
	if err == nil {
		t.Fatal("expected invalid mode error")
	}
}

func TestEndpointClientModeRejectsServerFields(t *testing.T) {
	_, err := NewEndpoint(nil, nil, nil, "client-server-fields", option.MasqueEndpointOptions{
		ServerOptions: option.ServerOptions{Server: "example.com", ServerPort: 443},
		HopPolicy:     option.MasqueHopPolicySingle,
		Listen:        "0.0.0.0",
		ListenPort:    8443,
	})
	if err == nil {
		t.Fatal("expected client mode to reject server listen fields")
	}
}

func TestEndpointClientModeRejectsServerPortPolicies(t *testing.T) {
	_, err := NewEndpoint(nil, nil, nil, "client-port-policy", option.MasqueEndpointOptions{
		ServerOptions:      option.ServerOptions{Server: "example.com", ServerPort: 443},
		HopPolicy:          option.MasqueHopPolicySingle,
		AllowedTargetPorts: []uint16{443},
		BlockedTargetPorts: []uint16{25},
	})
	if err == nil {
		t.Fatal("expected client mode to reject server target port policy fields")
	}
}

func TestEndpointClientModeRejectsAllowPrivateTargets(t *testing.T) {
	_, err := NewEndpoint(nil, nil, nil, "client-allow-private-targets", option.MasqueEndpointOptions{
		ServerOptions:       option.ServerOptions{Server: "example.com", ServerPort: 443},
		HopPolicy:           option.MasqueHopPolicySingle,
		TCPTransport:        option.MasqueTCPTransportConnectStream,
		AllowPrivateTargets: true,
	})
	if err == nil {
		t.Fatal("expected client mode to reject server-only allow_private_targets field")
	}
}

func TestEndpointClientModeAllowsServerToken(t *testing.T) {
	_, err := NewEndpoint(nil, nil, nil, "client-server-token", option.MasqueEndpointOptions{
		ServerOptions: option.ServerOptions{Server: "example.com", ServerPort: 443},
		HopPolicy:     option.MasqueHopPolicySingle,
		ServerToken:   "shared-token",
		TCPTransport:  option.MasqueTCPTransportConnectStream,
	})
	if err != nil {
		t.Fatalf("expected client mode to allow server_token for auth contract, got %v", err)
	}
}

func TestEndpointRejectsAutoTCPTransportInClientMode(t *testing.T) {
	_, err := NewEndpoint(nil, nil, nil, "client-auto-tcp-transport", option.MasqueEndpointOptions{
		ServerOptions: option.ServerOptions{Server: "example.com", ServerPort: 443},
		HopPolicy:     option.MasqueHopPolicySingle,
		TCPTransport:  option.MasqueTCPTransportAuto,
	})
	if err == nil {
		t.Fatal("expected client mode to reject tcp_transport=auto")
	}
}

func TestEndpointRejectsImplicitTCPTransportInClientMode(t *testing.T) {
	_, err := NewEndpoint(nil, nil, nil, "client-implicit-tcp-transport", option.MasqueEndpointOptions{
		ServerOptions: option.ServerOptions{Server: "example.com", ServerPort: 443},
		HopPolicy:     option.MasqueHopPolicySingle,
	})
	if err == nil {
		t.Fatal("expected client mode to reject implicit tcp_transport default")
	}
}

func TestEndpointRejectsClientTemplateTCPWithoutPlaceholders(t *testing.T) {
	_, err := NewEndpoint(nil, nil, nil, "client-template-tcp", option.MasqueEndpointOptions{
		ServerOptions: option.ServerOptions{Server: "example.com", ServerPort: 443},
		HopPolicy:     option.MasqueHopPolicySingle,
		TCPTransport:  option.MasqueTCPTransportConnectStream,
		TemplateTCP:   "https://example.com/masque/tcp",
	})
	if err == nil {
		t.Fatal("expected client mode template_tcp placeholder validation error")
	}
}

func TestEndpointRejectsClientTemplateUDPWithoutPlaceholders(t *testing.T) {
	_, err := NewEndpoint(nil, nil, nil, "client-template-udp", option.MasqueEndpointOptions{
		ServerOptions: option.ServerOptions{Server: "example.com", ServerPort: 443},
		HopPolicy:     option.MasqueHopPolicySingle,
		TCPTransport:  option.MasqueTCPTransportConnectStream,
		TemplateUDP:   "https://example.com/masque/udp",
	})
	if err == nil {
		t.Fatal("expected client mode template_udp placeholder validation error")
	}
}

func TestEndpointRejectsServerTemplateUDPWithoutPlaceholders(t *testing.T) {
	_, err := NewEndpoint(nil, nil, nil, "server-template-udp", option.MasqueEndpointOptions{
		Mode:        option.MasqueModeServer,
		Listen:      "127.0.0.1",
		ListenPort:  8443,
		Certificate: "cert.pem",
		Key:         "key.pem",
		TemplateUDP: "https://example.com/masque/udp",
	})
	if err == nil {
		t.Fatal("expected server mode template_udp placeholder validation error")
	}
}

func TestEndpointRejectsServerTemplatePathCollisions(t *testing.T) {
	_, err := NewEndpoint(nil, nil, nil, "server-template-path-collision", option.MasqueEndpointOptions{
		Mode:        option.MasqueModeServer,
		Listen:      "127.0.0.1",
		ListenPort:  8443,
		Certificate: "cert.pem",
		Key:         "key.pem",
		TemplateUDP: "https://example.com/masque/shared/{target_host}/{target_port}",
		TemplateIP:  "https://example.com/masque/shared/{target_host}/{target_port}",
	})
	if err == nil {
		t.Fatal("expected server mode template path collision validation error")
	}
}

func TestEndpointRejectsConnectIPTCPTransportInTunOnlyMode(t *testing.T) {
	_, err := NewEndpoint(nil, nil, nil, "connect-ip-tcp-transport", option.MasqueEndpointOptions{
		ServerOptions: option.ServerOptions{Server: "example.com", ServerPort: 443},
		HopPolicy:     option.MasqueHopPolicySingle,
		TCPTransport:  option.MasqueTCPTransportConnectIP,
	})
	if err == nil {
		t.Fatal("expected connect_ip tcp transport to be rejected in TUN-only mode")
	}
}

func TestEndpointScopeFieldsRequireConnectIPTransportMode(t *testing.T) {
	_, err := NewEndpoint(nil, nil, nil, "scope-without-connect-ip", option.MasqueEndpointOptions{
		ServerOptions:         option.ServerOptions{Server: "example.com", ServerPort: 443},
		HopPolicy:             option.MasqueHopPolicySingle,
		TransportMode:         option.MasqueTransportModeConnectUDP,
		ConnectIPScopeTarget:  "10.0.0.0/8",
		ConnectIPScopeIPProto: 17,
	})
	if err == nil {
		t.Fatal("expected connect_ip_scope_* to be rejected when transport_mode!=connect_ip")
	}
}

func TestEndpointScopeFieldsRequireTemplateIPFlowVariables(t *testing.T) {
	_, err := NewEndpoint(nil, nil, nil, "scope-missing-template-vars", option.MasqueEndpointOptions{
		ServerOptions:         option.ServerOptions{Server: "example.com", ServerPort: 443},
		HopPolicy:             option.MasqueHopPolicySingle,
		TransportMode:         option.MasqueTransportModeConnectIP,
		TCPTransport:          option.MasqueTCPTransportConnectStream,
		TemplateIP:            "https://example.com/masque/ip",
		ConnectIPScopeTarget:  "10.0.0.0/8",
		ConnectIPScopeIPProto: 17,
	})
	if err == nil {
		t.Fatal("expected connect_ip_scope_* to require template_ip flow forwarding variables")
	}
}

func TestEndpointRejectsQUICExperimentalWithoutEnv(t *testing.T) {
	prev := os.Getenv("MASQUE_EXPERIMENTAL_QUIC")
	defer os.Setenv("MASQUE_EXPERIMENTAL_QUIC", prev)
	_ = os.Setenv("MASQUE_EXPERIMENTAL_QUIC", "")
	_, err := NewEndpoint(nil, nil, nil, "quic-exp-no-env", option.MasqueEndpointOptions{
		ServerOptions: option.ServerOptions{Server: "example.com", ServerPort: 443},
		HopPolicy:     option.MasqueHopPolicySingle,
		QUICExperimental: &option.MasqueQUICExperimentalOptions{
			Enabled: true,
		},
	})
	if err == nil {
		t.Fatal("expected quic_experimental.enabled to require MASQUE_EXPERIMENTAL_QUIC=1")
	}
}

func TestServerEndpointAuthorizeRequest(t *testing.T) {
	ep := &ServerEndpoint{
		options: option.MasqueEndpointOptions{
			ServerToken: "secret-token",
		},
	}
	req, _ := http.NewRequest(http.MethodConnect, "https://example.com/masque/tcp/example.com/443", nil)
	if ep.authorizeRequest(req) {
		t.Fatal("expected unauthorized request without token header")
	}
	req.Header.Set("Authorization", "Bearer secret-token")
	if !ep.authorizeRequest(req) {
		t.Fatal("expected authorization success for valid bearer token")
	}
}

func TestAllowTCPTargetBlocksPrivateByDefault(t *testing.T) {
	if _, err := resolveTCPTargetForDial(context.Background(), "127.0.0.1", false); err == nil {
		t.Fatal("expected localhost to be denied by default")
	}
	if _, err := resolveTCPTargetForDial(context.Background(), "192.168.1.10", false); err == nil {
		t.Fatal("expected private address to be denied by default")
	}
	if resolved, err := resolveTCPTargetForDial(context.Background(), "1.1.1.1", false); err != nil || resolved == "" {
		t.Fatal("expected public address to be allowed")
	}
	if _, err := resolveTCPTargetForDial(context.Background(), "localhost", true); err != nil {
		t.Fatal("expected allow_private_targets=true to allow local targets")
	}
}

func TestAllowTCPPortPolicy(t *testing.T) {
	if !allowTCPPort("443", nil, nil) {
		t.Fatal("expected 443 to be allowed without policies")
	}
	if allowTCPPort("25", nil, []uint16{25}) {
		t.Fatal("expected blocked port to be denied")
	}
	if allowTCPPort("80", []uint16{443}, nil) {
		t.Fatal("expected port outside allowlist to be denied")
	}
	if !allowTCPPort("443", []uint16{443, 8443}, []uint16{25}) {
		t.Fatal("expected allowlisted port to pass")
	}
}

func TestParseTCPTargetFromRequestRejectsMalformedTarget(t *testing.T) {
	template, err := uritemplate.New("https://example.com/masque/tcp/{target_host}/{target_port}")
	if err != nil {
		t.Fatalf("template init: %v", err)
	}
	req, _ := http.NewRequest(http.MethodConnect, "https://example.com/masque/tcp//bad", nil)
	if _, _, err := parseTCPTargetFromRequest(req, template); err == nil {
		t.Fatal("expected malformed target to be rejected")
	}
}

func TestWarpEndpointCloseBeforeAsyncStartCompletes(t *testing.T) {
	epRaw, err := NewWarpEndpoint(nil, nil, nil, "wm-close-race", option.WarpMasqueEndpointOptions{
		MasqueEndpointOptions: option.MasqueEndpointOptions{
			HopPolicy:    option.MasqueHopPolicySingle,
			TCPTransport: option.MasqueTCPTransportConnectStream,
		},
	})
	if err != nil {
		t.Fatalf("new warp endpoint: %v", err)
	}
	ep := epRaw.(*WarpEndpoint)
	ep.bootstrapF = func(ctx context.Context) (string, uint16, error) {
		time.Sleep(80 * time.Millisecond)
		return "engage.cloudflareclient.com", 443, nil
	}
	if err := ep.Start(adapter.StartStatePostStart); err != nil {
		t.Fatalf("start warp endpoint: %v", err)
	}
	if err := ep.Close(); err != nil {
		t.Fatalf("close warp endpoint: %v", err)
	}
	time.Sleep(120 * time.Millisecond)
	if ep.IsReady() {
		t.Fatal("endpoint must stay not ready after close-before-start race")
	}
}

func TestWarpEndpointStartupInProgressIsTransportInit(t *testing.T) {
	epRaw, err := NewWarpEndpoint(nil, nil, nil, "wm-in-progress", option.WarpMasqueEndpointOptions{
		MasqueEndpointOptions: option.MasqueEndpointOptions{
			HopPolicy:    option.MasqueHopPolicySingle,
			TCPTransport: option.MasqueTCPTransportConnectStream,
		},
	})
	if err != nil {
		t.Fatalf("new warp endpoint: %v", err)
	}
	ep := epRaw.(*WarpEndpoint)
	ep.bootstrapF = func(ctx context.Context) (string, uint16, error) {
		<-ctx.Done()
		return "", 0, ctx.Err()
	}
	if err := ep.Start(adapter.StartStatePostStart); err != nil {
		t.Fatalf("start warp endpoint: %v", err)
	}
	_, err = ep.DialContext(context.Background(), "tcp", M.Socksaddr{})
	if err == nil {
		t.Fatal("expected startup-in-progress error")
	}
	if !errors.Is(err, TM.ErrTransportInit) {
		t.Fatalf("expected ErrTransportInit sentinel, got %v", err)
	}
}

func TestWarpEndpointListenPacketStartupInProgressIsTransportInit(t *testing.T) {
	epRaw, err := NewWarpEndpoint(nil, nil, nil, "wm-listen-in-progress", option.WarpMasqueEndpointOptions{
		MasqueEndpointOptions: option.MasqueEndpointOptions{
			HopPolicy:    option.MasqueHopPolicySingle,
			TCPTransport: option.MasqueTCPTransportConnectStream,
		},
	})
	if err != nil {
		t.Fatalf("new warp endpoint: %v", err)
	}
	ep := epRaw.(*WarpEndpoint)
	ep.bootstrapF = func(ctx context.Context) (string, uint16, error) {
		<-ctx.Done()
		return "", 0, ctx.Err()
	}
	if err := ep.Start(adapter.StartStatePostStart); err != nil {
		t.Fatalf("start warp endpoint: %v", err)
	}
	_, err = ep.ListenPacket(context.Background(), M.Socksaddr{})
	if err == nil {
		t.Fatal("expected startup-in-progress error")
	}
	if !errors.Is(err, TM.ErrTransportInit) {
		t.Fatalf("expected ErrTransportInit sentinel, got %v", err)
	}
}

func TestWarpEndpointListenPacketStartupFailedPreservesCause(t *testing.T) {
	epRaw, err := NewWarpEndpoint(nil, nil, nil, "wm-listen-startup-failed", option.WarpMasqueEndpointOptions{
		MasqueEndpointOptions: option.MasqueEndpointOptions{
			HopPolicy:    option.MasqueHopPolicySingle,
			TCPTransport: option.MasqueTCPTransportConnectStream,
		},
	})
	if err != nil {
		t.Fatalf("new warp endpoint: %v", err)
	}
	ep := epRaw.(*WarpEndpoint)
	startCause := errors.New("bootstrap failed hard")
	ep.startErr.Store(startCause)
	_, err = ep.ListenPacket(context.Background(), M.Socksaddr{})
	if err == nil {
		t.Fatal("expected startup-failed error")
	}
	if !errors.Is(err, TM.ErrTransportInit) {
		t.Fatalf("expected ErrTransportInit sentinel, got %v", err)
	}
	if !errors.Is(err, startCause) {
		t.Fatalf("expected startup cause to be preserved, got %v", err)
	}
}
