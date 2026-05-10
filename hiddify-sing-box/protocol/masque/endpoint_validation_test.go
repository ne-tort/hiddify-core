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
	// Canonical quic-go/http3 client refusal (capital Extended CONNECT) must stay h3_extended_connect
	// for metrics/WARP port policy, not "other" or h2_*.
	if g, w := ClassifyMasqueFailure(errors.New("http3: server didn't enable Extended CONNECT")), "h3_extended_connect"; g != w {
		t.Fatalf("http3 extended connect: got %q want %q", g, w)
	}
	if g, w := ClassifyMasqueFailure(errors.New("connect-ip: server didn't enable Extended CONNECT")), "h3_extended_connect"; g != w {
		t.Fatalf("got %q want %q", g, w)
	}
	if g, w := ClassifyMasqueFailure(errors.New("masque: server didn't enable Extended CONNECT")), "h3_extended_connect"; g != w {
		t.Fatalf("masque-go extended connect: got %q want %q", g, w)
	}
	if g, w := ClassifyMasqueFailure(errors.New("http3: server didn't enable extended connect")), "h3_extended_connect"; g != w {
		t.Fatalf("lowercase extended connect token must classify as h3: got %q want %q", g, w)
	}
	if g, w := ClassifyMasqueFailure(errors.New("masque h2: roundtrip: EOF")), "h2_masque_handshake"; g != w {
		t.Fatalf("h2 prefix: got %q want %q", g, w)
	}
	if g, w := ClassifyMasqueFailure(errors.New("masque h2: tcp connect-stream status 502")), "h2_masque_handshake"; g != w {
		t.Fatalf("h2 CONNECT-stream prefix: got %q want %q", g, w)
	}
	if g, w := ClassifyMasqueFailure(errors.New("masque h2: CONNECT-UDP status 401")), "connect_http_auth"; g != w {
		t.Fatalf("H2 CONNECT-UDP HTTP 401 must classify as auth (not h2 handshake bucket): got %q want %q", g, w)
	}
	if g, w := ClassifyMasqueFailure(errors.New("masque connect-ip h2: dial: server responded with 403")), "connect_http_auth"; g != w {
		t.Fatalf("CONNECT-IP H2 HTTP 403 under masque prefix: got %q want %q", g, w)
	}
	if g, w := ClassifyMasqueFailure(errors.New("http2: server rejected ENABLE_CONNECT_PROTOCOL")), "h2_extended_connect_rfc8441"; g != w {
		t.Fatalf("rfc8441 settings: got %q want %q", g, w)
	}
	if g, w := ClassifyMasqueFailure(errors.New("net/http: extended connect not supported by peer")), "h2_extended_connect_rfc8441"; g != w {
		t.Fatalf("http2 peer no extended connect: got %q want %q", g, w)
	}
	if g, w := ClassifyMasqueFailure(errors.New("net/http: Extended Connect Not Supported by peer")), "h2_extended_connect_rfc8441"; g != w {
		t.Fatalf("http2 RFC8441 failure must classify case-insensitively: got %q want %q", g, w)
	}
	if g, w := ClassifyMasqueFailure(errors.New("masque h2 dataplane connect-udp capsule: truncated")), "other"; g != w {
		t.Fatalf("H2 CONNECT-UDP dataplane errors must stay other: got %q want %q", g, w)
	}
	if g, w := ClassifyMasqueFailure(errors.New("masque h2 dataplane connect-udp server capsule: bogus")), "other"; g != w {
		t.Fatalf("H2 CONNECT-UDP server relay dataplane must stay other: got %q want %q", g, w)
	}
	if g, w := ClassifyMasqueFailure(errors.New("masque h2: dataplane connect-udp capsule: corrupt framing")), "other"; g != w {
		t.Fatalf("colon-typo H2 dataplane label must stay other (not handshake): got %q want %q", g, w)
	}
	if g, w := ClassifyMasqueFailure(errors.New("masque connect-ip h2 dataplane: DATAGRAM capsule truncated")), "other"; g != w {
		t.Fatalf("CONNECT-IP H2 dataplane label must stay other: got %q want %q", g, w)
	}
	if g, w := ClassifyMasqueFailure(errors.New("masque connect-ip h3 dataplane: ReceiveDatagram: QUIC extended connect stale")), "other"; g != w {
		t.Fatalf("CONNECT-IP H3 dataplane label must stay other: got %q want %q", g, w)
	}
	// dialConnectIPHTTP2 wraps DialHTTP2 errors with "masque connect-ip h2:" (handshake / transport).
	if g, w := ClassifyMasqueFailure(errors.New("masque connect-ip h2: HTTP/2 roundtrip: EOF")), "h2_masque_handshake"; g != w {
		t.Fatalf("CONNECT-IP H2 wrapper handshake bucket: got %q want %q", g, w)
	}
	if g, w := ClassifyMasqueFailure(errors.New("masque connect-ip h2: tls: handshake failure")), "h2_masque_handshake"; g != w {
		t.Fatalf("CONNECT-IP H2 TLS under wrapper: got %q want %q", g, w)
	}
	if g, w := ClassifyMasqueFailure(errors.New(`masque h3 dataplane connect-stream read: QUIC: extended connect noise from stack`)), "other"; g != w {
		t.Fatalf("classify mismatch: got %q want %q", g, w)
	}
	if g, w := ClassifyMasqueFailure(errors.New(`masque h3 dataplane connect-udp write: QUIC: nested Extended CONNECT`)), "other"; g != w {
		t.Fatalf("H3 CONNECT-UDP dataplane must stay other (not h3_extended_connect): got %q want %q", g, w)
	}
	if g, w := ClassifyMasqueFailure(errors.New(`masque h2 dataplane connect-stream read: http2: stream ended`)), "other"; g != w {
		t.Fatalf("H2 CONNECT-stream dataplane label must stay other (not handshake): got %q want %q", g, w)
	}
	if g, w := ClassifyMasqueFailure(errors.New("http2: received GOAWAY with error code INTERNAL_ERROR")), "h2_masque_handshake"; g != w {
		t.Fatalf("bare http2 error must map to handshake (not dataplane-other): got %q want %q", g, w)
	}
	if g, w := ClassifyMasqueFailure(errors.New("masque connect-udp h3 skip-capsules: type=1 capsule exceeds 65536 bytes")), "other"; g != w {
		t.Fatalf("H3 CONNECT-UDP skip-capsules drain must stay other: got %q want %q", g, w)
	}
	// Markers are matched on lowercased text so metrics/WARP classification stay stable for wrapped errors.
	if g, w := ClassifyMasqueFailure(errors.New("MASQUE H2 dataplane connect-udp capsule: truncated")), "other"; g != w {
		t.Fatalf("mixed-case H2 dataplane must stay other: got %q want %q", g, w)
	}
	if g, w := ClassifyMasqueFailure(errors.New("MASQUE H2: tcp connect-stream rejected")), "h2_masque_handshake"; g != w {
		t.Fatalf("mixed-case H2 handshake prefix: got %q want %q", g, w)
	}
	if g, w := ClassifyMasqueFailure(errors.New(`http3: server didn't enable Datagrams for this connection`)), "h3_datagrams"; g != w {
		t.Fatalf("mixed-case datagrams gate: got %q want %q", g, w)
	}
	if g, w := ClassifyMasqueFailure(errors.New("connect-ip: server responded with 403")), "connect_http_auth"; g != w {
		t.Fatalf("HTTP 403 must classify like 401 for WARP port policy: got %q want %q", g, w)
	}
	if g, w := ClassifyMasqueFailure(errors.New("connect-ip: server responded with 407")), "connect_http_auth"; g != w {
		t.Fatalf("HTTP 407 must classify like 401 for WARP port policy: got %q want %q", g, w)
	}
	if g, w := ClassifyMasqueFailure(errors.New("dial udp 192.0.2.1:1401: connection refused")), "other"; g != w {
		t.Fatalf("UDP dial to port 1401 must not match HTTP 401 via substring: got %q want %q", g, w)
	}
	if g, w := ClassifyMasqueFailure(errors.New("dial udp 203.0.113.9:84403: i/o timeout")), "other"; g != w {
		t.Fatalf("UDP dial to port 84403 must not match HTTP 403 via substring: got %q want %q", g, w)
	}
}

func TestValidateMasqueHTTPLayerH2VersusQuicExperimental(t *testing.T) {
	opts := option.MasqueEndpointOptions{
		ServerOptions: option.ServerOptions{Server: "x", ServerPort: 443},
		TransportMode: option.MasqueTransportModeConnectUDP,
		TCPTransport:  option.MasqueTCPTransportConnectStream,
		HTTPLayer:     option.MasqueHTTPLayerH2,
		QUICExperimental: &option.MasqueQUICExperimentalOptions{
			Enabled: true,
		},
	}
	if err := validateMasqueOptions(opts); err == nil {
		t.Fatal("expected error: h2 vs quic_experimental")
	}
}

func TestValidateMasqueHTTPLayerH2AllowsConnectIP(t *testing.T) {
	opts := option.MasqueEndpointOptions{
		ServerOptions: option.ServerOptions{Server: "x", ServerPort: 443},
		TransportMode: option.MasqueTransportModeConnectIP,
		TCPTransport:  option.MasqueTCPTransportConnectIP,
		HTTPLayer:     option.MasqueHTTPLayerH2,
	}
	if err := validateMasqueOptions(opts); err != nil {
		t.Fatalf("expected h2 + connect_ip to validate: %v", err)
	}
}

func TestValidateMasqueHTTPLayerH2AllowsTCPConnectStream(t *testing.T) {
	opts := option.MasqueEndpointOptions{
		ServerOptions: option.ServerOptions{Server: "x", ServerPort: 443},
		TransportMode: option.MasqueTransportModeConnectUDP,
		TCPTransport:  option.MasqueTCPTransportConnectStream,
		HTTPLayer:     option.MasqueHTTPLayerH2,
	}
	if err := validateMasqueOptions(opts); err != nil {
		t.Fatalf("expected h2 + connect_stream to validate: %v", err)
	}
}

func TestValidateMasqueOptionsRejectsCacheTTLWithoutAutoHTTPLayer(t *testing.T) {
	opts := option.MasqueEndpointOptions{
		ServerOptions:     option.ServerOptions{Server: "x", ServerPort: 443},
		TransportMode:     option.MasqueTransportModeConnectUDP,
		TCPTransport:      option.MasqueTCPTransportConnectStream,
		HTTPLayer:         option.MasqueHTTPLayerH2,
		HTTPLayerCacheTTL: badoption.Duration(5 * time.Minute),
	}
	if err := validateMasqueOptions(opts); err == nil {
		t.Fatal("expected error: cache_ttl without auto")
	}
}

func TestValidateMasqueOptionsAllowsCacheTTLWithAutoHTTPLayer(t *testing.T) {
	opts := option.MasqueEndpointOptions{
		ServerOptions:     option.ServerOptions{Server: "x", ServerPort: 443},
		TransportMode:     option.MasqueTransportModeConnectUDP,
		TCPTransport:      option.MasqueTCPTransportConnectStream,
		HTTPLayer:         option.MasqueHTTPLayerAuto,
		HTTPLayerCacheTTL: badoption.Duration(5 * time.Minute),
	}
	if err := validateMasqueOptions(opts); err != nil {
		t.Fatalf("expected auto + cache_ttl to validate: %v", err)
	}
}

func TestNormalizeHTTPLayerEmpty(t *testing.T) {
	if g, w := normalizeHTTPLayer(""), option.MasqueHTTPLayerH3; g != w {
		t.Fatalf("normalize empty: got %q want %q", g, w)
	}
	if g, w := normalizeHTTPLayer(" "), option.MasqueHTTPLayerH3; g != w {
		t.Fatalf("normalize blank: got %q want %q", g, w)
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
	if IsRetryableWarpMasqueDataplanePort(errors.New("connect-ip: server responded with 403")) {
		t.Fatal("403 must not rotate ports")
	}
	if IsRetryableWarpMasqueDataplanePort(errors.New("CONNECT failed: 407 Proxy Authentication Required")) {
		t.Fatal("407 must not rotate ports")
	}
	if !IsRetryableWarpMasqueDataplanePort(errors.New("dial udp 192.0.2.1:1401: connection refused")) {
		t.Fatal("port 1401 dial failure is not HTTP 401; must remain retryable for WARP port sweep")
	}
	if IsRetryableWarpMasqueDataplanePort(errors.New("http2: received GOAWAY with error code ENHANCE_YOUR_CALM")) {
		t.Fatal("bare golang.org/x/net/http2 errors must classify as h2 handshake, not dataplane-port spin")
	}
}
