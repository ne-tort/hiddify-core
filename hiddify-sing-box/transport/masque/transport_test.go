package masque

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	connectip "github.com/quic-go/connect-ip-go"
	qmasque "github.com/quic-go/masque-go"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/yosida95/uritemplate/v3"
)

type timeoutNetError struct{ msg string }

func (e timeoutNetError) Error() string   { return e.msg }
func (e timeoutNetError) Timeout() bool   { return true }
func (e timeoutNetError) Temporary() bool { return false }

func TestResolveEntryHopSingleEntry(t *testing.T) {
	server, port, err := resolveEntryHop([]HopOptions{
		{Tag: "a", Server: "a.example", Port: 443},
		{Tag: "b", Via: "a", Server: "b.example", Port: 8443},
	})
	if err != nil {
		t.Fatalf("resolve entry hop: %v", err)
	}
	if server != "a.example" || port != 443 {
		t.Fatalf("unexpected entry hop %s:%d", server, port)
	}
}

func TestResolveEntryHopMultipleEntriesRejected(t *testing.T) {
	_, _, err := resolveEntryHop([]HopOptions{
		{Tag: "a", Server: "a.example", Port: 443},
		{Tag: "b", Server: "b.example", Port: 443},
	})
	if err == nil {
		t.Fatal("expected multiple entry hops error")
	}
}

func TestResolveHopOrderLinearChain(t *testing.T) {
	ordered := resolveHopOrder([]HopOptions{
		{Tag: "h2", Via: "h1", Server: "h2.example", Port: 443},
		{Tag: "h1", Server: "h1.example", Port: 443},
		{Tag: "h3", Via: "h2", Server: "h3.example", Port: 443},
	})
	if len(ordered) != 3 {
		t.Fatalf("unexpected hop order length: %d", len(ordered))
	}
	if ordered[0].Tag != "h1" || ordered[1].Tag != "h2" || ordered[2].Tag != "h3" {
		t.Fatalf("unexpected hop order: %+v", ordered)
	}
}

func TestResolveHopOrderDisconnectedGraphFallsBackToInputOrder(t *testing.T) {
	input := []HopOptions{
		{Tag: "orphan", Via: "missing", Server: "orphan.example", Port: 443},
		{Tag: "entry", Server: "entry.example", Port: 8443},
	}
	ordered := resolveHopOrder(input)
	if len(ordered) != len(input) {
		t.Fatalf("unexpected hop order length: %d", len(ordered))
	}
	for i := range input {
		if ordered[i].Tag != input[i].Tag {
			t.Fatalf("expected fallback to input order for disconnected chain, got: %+v", ordered)
		}
	}
}

func TestResolveHopOrderBranchingGraphFallsBackToInputOrder(t *testing.T) {
	input := []HopOptions{
		{Tag: "entry", Server: "entry.example", Port: 443},
		{Tag: "left", Via: "entry", Server: "left.example", Port: 8443},
		{Tag: "right", Via: "entry", Server: "right.example", Port: 9443},
	}
	ordered := resolveHopOrder(input)
	if len(ordered) != len(input) {
		t.Fatalf("unexpected hop order length: %d", len(ordered))
	}
	for i := range input {
		if ordered[i].Tag != input[i].Tag {
			t.Fatalf("expected fallback to input order for branching chain, got: %+v", ordered)
		}
	}
}

func TestMasqueDialTargetPreservesHostname(t *testing.T) {
	target := masqueDialTarget("engage.cloudflareclient.com", 443)
	if target != "engage.cloudflareclient.com:443" {
		t.Fatalf("unexpected target: %s", target)
	}
}

func TestResolveEntryHopNoEntryRejected(t *testing.T) {
	_, _, err := resolveEntryHop([]HopOptions{
		{Tag: "a", Via: "b", Server: "a.example", Port: 443},
		{Tag: "b", Via: "a", Server: "b.example", Port: 443},
	})
	if err == nil {
		t.Fatal("expected no entry hop error")
	}
}

func TestCoreSessionAdvanceHop(t *testing.T) {
	session := &coreSession{
		hopOrder: []HopOptions{
			{Tag: "h1", Server: "h1.example", Port: 443},
			{Tag: "h2", Via: "h1", Server: "h2.example", Port: 8443},
		},
	}
	if !session.advanceHop() {
		t.Fatal("expected first advanceHop to succeed")
	}
	if session.hopIndex != 1 {
		t.Fatalf("unexpected hop index: %d", session.hopIndex)
	}
	if session.advanceHop() {
		t.Fatal("expected second advanceHop to fail at chain end")
	}
}

func TestResetHopTemplatesClearsTCPHTTPTransport(t *testing.T) {
	session := &coreSession{
		options: ClientOptions{
			Server: "entry.example",
			Hops: []HopOptions{
				{Tag: "entry", Server: "entry.example", Port: 443},
				{Tag: "next", Via: "entry", Server: "next.example", Port: 8443},
			},
		},
		hopOrder: []HopOptions{
			{Tag: "entry", Server: "entry.example", Port: 443},
			{Tag: "next", Via: "entry", Server: "next.example", Port: 8443},
		},
		hopIndex: 1,
		tcpHTTP:  &http3.Transport{},
	}

	if err := session.resetHopTemplates(); err != nil {
		t.Fatalf("resetHopTemplates failed: %v", err)
	}
	if session.tcpHTTP != nil {
		t.Fatal("expected tcpHTTP transport cache to be cleared on hop reset")
	}
}

func TestBuildTemplatesIncludesTCPTemplate(t *testing.T) {
	udp, ip, tcp, err := buildTemplates(ClientOptions{
		Server:     "example.com",
		ServerPort: 443,
	})
	if err != nil {
		t.Fatalf("buildTemplates failed: %v", err)
	}
	if udp == nil || ip == nil || tcp == nil {
		t.Fatal("expected udp/ip/tcp templates to be initialized")
	}
}

func TestBuildTemplatesDefaultsServerPortTo443WhenZero(t *testing.T) {
	udp, ip, tcp, err := buildTemplates(ClientOptions{
		Server: "example.com",
	})
	if err != nil {
		t.Fatalf("buildTemplates failed with implicit server port: %v", err)
	}
	if got := udp.Raw(); !strings.Contains(got, "https://example.com:443/masque/udp/") {
		t.Fatalf("unexpected udp template default server_port wiring: %s", got)
	}
	if got := ip.Raw(); got != "https://example.com:443/masque/ip" {
		t.Fatalf("unexpected ip template default server_port wiring: %s", got)
	}
	if got := tcp.Raw(); !strings.Contains(got, "https://example.com:443/masque/tcp/") {
		t.Fatalf("unexpected tcp template default server_port wiring: %s", got)
	}
}

func TestBuildTemplatesUsesEntryHopServerWithDefaultPortWhenEntryPortZero(t *testing.T) {
	udp, ip, tcp, err := buildTemplates(ClientOptions{
		Server:     "fallback.example",
		ServerPort: 0,
		Hops: []HopOptions{
			{Tag: "entry", Server: "entry.example", Port: 0},
			{Tag: "next", Via: "entry", Server: "next.example", Port: 9443},
		},
	})
	if err != nil {
		t.Fatalf("buildTemplates failed for zero-port entry hop: %v", err)
	}
	if got := udp.Raw(); !strings.Contains(got, "https://entry.example:443/masque/udp/") {
		t.Fatalf("unexpected udp template entry-hop/default-port wiring: %s", got)
	}
	if got := ip.Raw(); got != "https://entry.example:443/masque/ip" {
		t.Fatalf("unexpected ip template entry-hop/default-port wiring: %s", got)
	}
	if got := tcp.Raw(); !strings.Contains(got, "https://entry.example:443/masque/tcp/") {
		t.Fatalf("unexpected tcp template entry-hop/default-port wiring: %s", got)
	}
}

func TestBuildTemplatesApplyConnectIPFlowScope(t *testing.T) {
	_, ip, _, err := buildTemplates(ClientOptions{
		Server:                "example.com",
		ServerPort:            443,
		TemplateIP:            "https://example.com/masque/ip/{target}/{ipproto}",
		ConnectIPScopeTarget:  "10.0.0.0/8",
		ConnectIPScopeIPProto: 6,
	})
	if err != nil {
		t.Fatalf("buildTemplates with scope failed: %v", err)
	}
	if got := ip.Raw(); got != "https://example.com/masque/ip/10.0.0.0%2F8/6" {
		t.Fatalf("unexpected expanded IP template: %s", got)
	}
}

func TestApplyConnectIPFlowScopeDefaults(t *testing.T) {
	expanded, err := applyConnectIPFlowScope("https://example.com/masque/ip/{target}/{ipproto}", "", 0)
	if err != nil {
		t.Fatalf("applyConnectIPFlowScope with defaults failed: %v", err)
	}
	if expanded != "https://example.com/masque/ip/0.0.0.0%2F0/0" {
		t.Fatalf("unexpected default expanded IP template: %s", expanded)
	}
}

func TestApplyConnectIPFlowScopeRejectsUnsupportedFlowVariable(t *testing.T) {
	_, err := applyConnectIPFlowScope("https://example.com/masque/ip/{target}/{scope_id}", "10.0.0.0/8", 17)
	if err == nil {
		t.Fatal("expected unsupported flow forwarding variable to fail fast")
	}
	if !errors.Is(err, ErrCapability) {
		t.Fatalf("expected ErrCapability for unsupported flow forwarding variable, got: %v", err)
	}
	if got := ClassifyError(err); got != ErrorClassCapability {
		t.Fatalf("expected capability class for unsupported flow forwarding variable, got: %s", got)
	}
}

func TestBuildTemplatesRejectScopeWithoutTemplateVars(t *testing.T) {
	_, _, _, err := buildTemplates(ClientOptions{
		Server:               "example.com",
		ServerPort:           443,
		TemplateIP:           "https://example.com/masque/ip",
		ConnectIPScopeTarget: "10.0.0.0/8",
	})
	if err == nil {
		t.Fatal("expected scope without flow-forwarding template variables to fail fast")
	}
}

func TestBuildTemplatesRejectInvalidScopeTarget(t *testing.T) {
	_, _, _, err := buildTemplates(ClientOptions{
		Server:               "example.com",
		ServerPort:           443,
		TemplateIP:           "https://example.com/masque/ip/{target}/{ipproto}",
		ConnectIPScopeTarget: "not-a-prefix",
	})
	if err == nil {
		t.Fatal("expected invalid connect_ip_scope_target to fail")
	}
}

func TestTransportMalformedScopedFlowBoundaryParity(t *testing.T) {
	actualClass, resultClass, err := ClassifyMalformedScopedTargetClassPair("not-a-prefix")
	if err == nil {
		t.Fatal("expected malformed scoped classification helper to fail for invalid target")
	}
	if actualClass != ErrorClassCapability {
		t.Fatalf("expected transport malformed scope classification capability, got: %s (err=%v)", actualClass, err)
	}
	if resultClass != ErrorClassCapability {
		t.Fatalf("expected wrapped malformed scope classification capability, got: %s (err=%v)", resultClass, err)
	}
	writeMalformedScopedTransportArtifactIfRequested(t, actualClass, resultClass)
}

func TestBuildScopedErrorArtifactNormalizesErrorSource(t *testing.T) {
	tests := []struct {
		name   string
		source string
		want   string
	}{
		{
			name:   "runtime",
			source: ErrorSourceRuntime,
			want:   ErrorSourceRuntime,
		},
		{
			name:   "compose_up",
			source: ErrorSourceComposeUp,
			want:   ErrorSourceComposeUp,
		},
		{
			name:   "empty_fallback_runtime",
			source: "",
			want:   ErrorSourceRuntime,
		},
		{
			name:   "unknown_fallback_runtime",
			source: "docker_boot",
			want:   ErrorSourceRuntime,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			artifact := BuildScopedErrorArtifact(ErrorClassCapability, ErrorClassCapability, tc.source)
			if artifact.ErrorSource != tc.want {
				t.Fatalf("unexpected artifact source: got=%s want=%s", artifact.ErrorSource, tc.want)
			}
		})
	}
}

func writeMalformedScopedTransportArtifactIfRequested(t *testing.T, actualClass, resultClass ErrorClass) {
	t.Helper()

	artifactPath := os.Getenv("MASQUE_MALFORMED_SCOPED_TRANSPORT_ARTIFACT_PATH")
	if artifactPath == "" {
		return
	}
	artifact := BuildScopedErrorArtifact(actualClass, resultClass, "runtime")
	raw, err := json.MarshalIndent(artifact, "", "  ")
	if err != nil {
		t.Fatalf("marshal malformed-scoped transport artifact: %v", err)
	}
	if err := os.WriteFile(artifactPath, raw, 0o644); err != nil {
		t.Fatalf("write malformed-scoped transport artifact: %v", err)
	}
}

func TestCoreClientFactoryConnectTCPCapabilityByTransport(t *testing.T) {
	streamSession, err := (CoreClientFactory{}).NewSession(nil, ClientOptions{
		Server:       "example.com",
		ServerPort:   443,
		TCPTransport: "connect_stream",
	})
	if err != nil {
		t.Fatalf("new connect_stream session: %v", err)
	}
	if !streamSession.Capabilities().ConnectTCP {
		t.Fatal("expected connect_stream session to advertise ConnectTCP")
	}

	ipSession, err := (CoreClientFactory{}).NewSession(nil, ClientOptions{
		Server:       "example.com",
		ServerPort:   443,
		TCPTransport: "connect_ip",
	})
	if err != nil {
		t.Fatalf("new connect_ip session: %v", err)
	}
	if ipSession.Capabilities().ConnectTCP {
		t.Fatal("expected connect_ip session to disable ConnectTCP in TUN-only mode")
	}
}

func TestDirectClientFactoryConnectTCPCapabilityByTransport(t *testing.T) {
	streamSession, err := (DirectClientFactory{}).NewSession(nil, ClientOptions{
		TCPTransport: "connect_stream",
	})
	if err != nil {
		t.Fatalf("new direct connect_stream session: %v", err)
	}
	if !streamSession.Capabilities().ConnectTCP {
		t.Fatal("expected direct connect_stream session to advertise ConnectTCP")
	}

	autoSession, err := (DirectClientFactory{}).NewSession(nil, ClientOptions{
		TCPTransport: "auto",
	})
	if err != nil {
		t.Fatalf("new direct auto session: %v", err)
	}
	if autoSession.Capabilities().ConnectTCP {
		t.Fatal("expected direct auto session to disable ConnectTCP")
	}

	ipSession, err := (DirectClientFactory{}).NewSession(nil, ClientOptions{
		TCPTransport: "connect_ip",
	})
	if err != nil {
		t.Fatalf("new direct connect_ip session: %v", err)
	}
	if ipSession.Capabilities().ConnectTCP {
		t.Fatal("expected direct connect_ip session to disable ConnectTCP in TUN-only mode")
	}
}

func TestCoreSessionDialContextRejectsNonTCPNetwork(t *testing.T) {
	session := &coreSession{
		options: ClientOptions{
			TCPTransport: "connect_stream",
		},
	}
	_, err := session.DialContext(context.Background(), "udp", M.ParseSocksaddrHostPort("example.com", 443))
	if err == nil {
		t.Fatal("expected non-tcp network to fail fast in core session")
	}
	if !errors.Is(err, ErrUnsupportedNetwork) {
		t.Fatalf("expected ErrUnsupportedNetwork for non-tcp core boundary reject, got: %v", err)
	}
	if !strings.Contains(err.Error(), "unsupported network in masque session") {
		t.Fatalf("unexpected non-tcp boundary error: %v", err)
	}
	if got := ClassifyError(err); got != ErrorClassCapability {
		t.Fatalf("expected capability class for non-tcp core boundary reject, got: %s", got)
	}
}

func TestDirectSessionDialContextRejectsNonTCPNetwork(t *testing.T) {
	session := &directSession{}
	_, err := session.DialContext(context.Background(), "udp", M.ParseSocksaddrHostPort("example.com", 443))
	if err == nil {
		t.Fatal("expected non-tcp network to fail fast in direct session")
	}
	if !errors.Is(err, ErrUnsupportedNetwork) {
		t.Fatalf("expected ErrUnsupportedNetwork for non-tcp direct boundary reject, got: %v", err)
	}
	if !strings.Contains(err.Error(), "unsupported network in masque session") {
		t.Fatalf("unexpected non-tcp boundary error: %v", err)
	}
	if got := ClassifyError(err); got != ErrorClassCapability {
		t.Fatalf("expected capability class for non-tcp direct boundary reject, got: %s", got)
	}
}

func TestDirectSessionDialContextAutoTransportReturnsPathNotImplemented(t *testing.T) {
	session := &directSession{tcpTransport: "auto"}
	_, err := session.DialContext(context.Background(), "tcp", M.ParseSocksaddrHostPort("example.com", 443))
	if err == nil {
		t.Fatal("expected direct session tcp_transport=auto to fail with deterministic path-not-implemented error")
	}
	if !errors.Is(err, ErrTCPPathNotImplemented) {
		t.Fatalf("expected ErrTCPPathNotImplemented, got: %v", err)
	}
	if got := ClassifyError(err); got != ErrorClassCapability {
		t.Fatalf("expected capability class for direct auto transport path reject, got: %s", got)
	}
}

func TestDirectSessionDialContextConnectIPReturnsTUNOnlyBoundary(t *testing.T) {
	session := &directSession{tcpTransport: "connect_ip"}
	_, err := session.DialContext(context.Background(), "tcp", M.ParseSocksaddrHostPort("example.com", 443))
	if err == nil {
		t.Fatal("expected direct session tcp_transport=connect_ip to fail as TUN-only TCP path")
	}
	if !errors.Is(err, ErrTCPOverConnectIP) {
		t.Fatalf("expected ErrTCPOverConnectIP, got: %v", err)
	}
	if got := ClassifyError(err); got != ErrorClassCapability {
		t.Fatalf("expected capability class for direct connect_ip tcp reject, got: %s", got)
	}
}

func TestDirectSessionOpenIPSessionReturnsCapabilityBoundary(t *testing.T) {
	session := &directSession{
		capabilities: CapabilitySet{ConnectIP: true},
	}
	_, err := session.OpenIPSession(context.Background())
	if err == nil {
		t.Fatal("expected direct session CONNECT-IP open to fail fast")
	}
	if !errors.Is(err, ErrCapability) {
		t.Fatalf("expected ErrCapability for direct backend CONNECT-IP boundary, got: %v", err)
	}
	if !strings.Contains(err.Error(), "CONNECT-IP is not available in direct backend") {
		t.Fatalf("unexpected direct backend CONNECT-IP boundary error: %v", err)
	}
	if got := ClassifyError(err); got != ErrorClassCapability {
		t.Fatalf("expected capability class for direct backend CONNECT-IP boundary reject, got: %s", got)
	}
}

func TestCoreSessionDialContextAutoTransportReturnsPathNotImplemented(t *testing.T) {
	session := &coreSession{
		options: ClientOptions{
			TCPTransport: "auto",
		},
	}
	_, err := session.DialContext(context.Background(), "tcp", M.ParseSocksaddrHostPort("example.com", 443))
	if err == nil {
		t.Fatal("expected tcp_transport=auto to fail with deterministic path-not-implemented error")
	}
	if !errors.Is(err, ErrTCPPathNotImplemented) {
		t.Fatalf("expected ErrTCPPathNotImplemented, got: %v", err)
	}
	if got := ClassifyError(err); got != ErrorClassCapability {
		t.Fatalf("expected capability class for auto transport path reject, got: %s", got)
	}
}

func TestCoreSessionDialContextConnectIPReturnsTUNOnlyBoundary(t *testing.T) {
	session := &coreSession{
		options: ClientOptions{
			TCPTransport: "connect_ip",
		},
	}
	_, err := session.DialContext(context.Background(), "tcp", M.ParseSocksaddrHostPort("example.com", 443))
	if err == nil {
		t.Fatal("expected tcp_transport=connect_ip to fail as TUN-only TCP path")
	}
	if !errors.Is(err, ErrTCPOverConnectIP) {
		t.Fatalf("expected ErrTCPOverConnectIP, got: %v", err)
	}
	if got := ClassifyError(err); got != ErrorClassCapability {
		t.Fatalf("expected capability class for connect_ip tcp reject, got: %s", got)
	}
}

func TestResolveDestinationHostRejectsInvalidDestination(t *testing.T) {
	_, err := resolveDestinationHost(M.Socksaddr{})
	if err == nil {
		t.Fatal("expected invalid destination to be rejected")
	}
	if !errors.Is(err, ErrCapability) {
		t.Fatalf("expected ErrCapability for invalid destination, got: %v", err)
	}
	if got := ClassifyError(err); got != ErrorClassCapability {
		t.Fatalf("expected capability class for invalid destination boundary reject, got: %s", got)
	}
}

func TestCoreSessionDialDirectTCPRejectsInvalidDestination(t *testing.T) {
	session := &coreSession{}
	_, err := session.dialDirectTCP(context.Background(), "tcp", M.Socksaddr{})
	if err == nil {
		t.Fatal("expected direct tcp dial to reject invalid destination")
	}
	if !errors.Is(err, ErrCapability) {
		t.Fatalf("expected ErrCapability for direct dial invalid destination, got: %v", err)
	}
	if got := ClassifyError(err); got != ErrorClassCapability {
		t.Fatalf("expected capability class for direct dial invalid destination, got: %s", got)
	}
}

func TestDirectSessionDialContextRejectsInvalidDestination(t *testing.T) {
	session := &directSession{tcpTransport: "connect_stream"}
	_, err := session.DialContext(context.Background(), "tcp", M.Socksaddr{})
	if err == nil {
		t.Fatal("expected direct session dial to reject invalid destination")
	}
	if !errors.Is(err, ErrCapability) {
		t.Fatalf("expected ErrCapability for direct session invalid destination, got: %v", err)
	}
	if got := ClassifyError(err); got != ErrorClassCapability {
		t.Fatalf("expected capability class for direct session invalid destination, got: %s", got)
	}
}

func TestClassifyError(t *testing.T) {
	if ClassifyError(errors.Join(ErrTCPDial, errors.New("dial failed"))) != ErrorClassDial {
		t.Fatal("expected tcp dial error class")
	}
	if ClassifyError(ErrPolicyFallbackDenied) != ErrorClassPolicy {
		t.Fatal("expected policy error class")
	}
	if ClassifyError(ErrAuthFailed) != ErrorClassAuth {
		t.Fatal("expected auth error class")
	}
	if ClassifyError(net.ErrClosed) != ErrorClassLifecycle {
		t.Fatal("expected lifecycle error class for net.ErrClosed")
	}
	if ClassifyError(&connectip.CloseError{Remote: true}) != ErrorClassLifecycle {
		t.Fatal("expected lifecycle error class for remote CloseError")
	}
	if ClassifyError(ErrUnsupportedNetwork) != ErrorClassCapability {
		t.Fatal("expected capability error class for unsupported network sentinel")
	}
}

func TestApplyQUICExperimentalOptions(t *testing.T) {
	cfg := applyQUICExperimentalOptions(nil, QUICExperimentalOptions{
		Enabled:                    true,
		KeepAlivePeriod:            5 * time.Second,
		MaxIdleTimeout:             10 * time.Second,
		InitialStreamReceiveWindow: 1234,
		MaxIncomingStreams:         8,
	})
	if cfg.KeepAlivePeriod != 5*time.Second {
		t.Fatal("expected keepalive period to be applied")
	}
	if cfg.MaxIdleTimeout != 10*time.Second {
		t.Fatal("expected max idle timeout to be applied")
	}
	if cfg.InitialStreamReceiveWindow != 1234 {
		t.Fatal("expected stream window to be applied")
	}
	if cfg.MaxIncomingStreams != 8 {
		t.Fatal("expected max incoming streams to be applied")
	}
}

func TestNewUDPClientSetsInitialPacketSizeBaseline(t *testing.T) {
	session := &coreSession{
		options: ClientOptions{},
	}
	client := session.newUDPClient()
	if client == nil || client.QUICConfig == nil {
		t.Fatal("expected udp client quic config")
	}
	if client.QUICConfig.InitialPacketSize == 0 {
		t.Fatal("expected non-zero udp initial packet size baseline")
	}
}

func TestStreamConnDeadlineUnsupported(t *testing.T) {
	c := &streamConn{
		reader: io.NopCloser(&fakeDeadlineReader{}),
		writer: &fakeWriter{},
	}
	if err := c.SetWriteDeadline(time.Now().Add(time.Second)); !errors.Is(err, ErrDeadlineUnsupported) {
		t.Fatalf("expected unsupported deadline error, got: %v", err)
	}
}

func TestWaitContextBackoffCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := waitContextBackoff(ctx, 2*time.Second); err == nil {
		t.Fatal("expected backoff to abort on cancelled context")
	}
}

func TestIsRetryableConnectIPError(t *testing.T) {
	if !isRetryableConnectIPError(&quic.IdleTimeoutError{}) {
		t.Fatal("expected timeout/no recent network activity to be retryable")
	}
	if !isRetryableConnectIPError(net.ErrClosed) {
		t.Fatal("expected closed network connection to be retryable")
	}
	if isRetryableConnectIPError(errors.New("authorization failed")) {
		t.Fatal("expected auth failures to be non-retryable")
	}
}

func TestIsRetryableTCPStreamError(t *testing.T) {
	if !isRetryableTCPStreamError(&quic.IdleTimeoutError{}) {
		t.Fatal("expected timeout/no recent network activity to be retryable")
	}
	if !isRetryableTCPStreamError(&quic.ApplicationError{ErrorCode: 0x100, Remote: true}) {
		t.Fatal("expected application errors to be retryable")
	}
	if isRetryableTCPStreamError(net.ErrClosed) {
		t.Fatal("expected closed network connection to be non-retryable for tcp stream path")
	}
}

func TestConnectIPPacketSessionDatagramCeiling(t *testing.T) {
	session := &connectIPPacketSession{datagramCeiling: 1280}
	_, err := session.WritePacket(make([]byte, 1400))
	if err == nil {
		t.Fatal("expected datagram ceiling error")
	}
}

func TestConnectIPPacketSessionCloseKeepsSharedConnOwnedByCoreSession(t *testing.T) {
	sharedConn := &connectip.Conn{}
	session := &coreSession{
		capabilities: CapabilitySet{ConnectIP: true},
		ipConn:       sharedConn,
	}
	wrapped, err := session.OpenIPSession(context.Background())
	if err != nil {
		t.Fatalf("open reused connect-ip session: %v", err)
	}
	if err := wrapped.Close(); err != nil {
		t.Fatalf("close wrapped connect-ip session: %v", err)
	}
	if session.ipConn != sharedConn {
		t.Fatal("expected wrapped close to keep coreSession shared connect-ip conn alive")
	}
	reused, err := session.OpenIPSession(context.Background())
	if err != nil {
		t.Fatalf("reopen reused connect-ip session: %v", err)
	}
	reusedWrapper, ok := reused.(*connectIPPacketSession)
	if !ok {
		t.Fatalf("unexpected ip session wrapper type: %T", reused)
	}
	if reusedWrapper.conn != sharedConn {
		t.Fatal("expected reopen path to reuse the same shared connect-ip conn")
	}
}

func TestCoreSessionCloseClearsConnectIPHTTPStateAndIsIdempotent(t *testing.T) {
	session := &coreSession{
		ipHTTP:     &http3.Transport{},
		ipHTTPConn: &http3.ClientConn{},
	}
	if err := session.Close(); err != nil {
		t.Fatalf("first close returned error: %v", err)
	}
	if session.ipHTTP != nil {
		t.Fatal("expected close to clear cached connect-ip http3 transport")
	}
	if session.ipHTTPConn != nil {
		t.Fatal("expected close to clear cached connect-ip http3 client conn")
	}
	if err := session.Close(); err != nil {
		t.Fatalf("second close should stay idempotent, got error: %v", err)
	}
}

func TestConnectIPDatagramCeilingMaxEnvContract(t *testing.T) {
	testCases := []struct {
		name      string
		envValue  string
		unsetEnv  bool
		expectMax int
	}{
		{name: "unset uses default", unsetEnv: true, expectMax: defaultConnectIPDatagramCeilingMax},
		{name: "valid override in range", envValue: "2048", expectMax: 2048},
		{name: "invalid text falls back", envValue: "not-a-number", expectMax: defaultConnectIPDatagramCeilingMax},
		{name: "below lower bound falls back", envValue: "1279", expectMax: defaultConnectIPDatagramCeilingMax},
		{name: "above upper bound falls back", envValue: "65536", expectMax: defaultConnectIPDatagramCeilingMax},
		{name: "trimmed valid override", envValue: " 4096 ", expectMax: 4096},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.unsetEnv {
				_ = os.Unsetenv("HIDDIFY_MASQUE_DATAGRAM_CEILING_MAX")
			} else {
				t.Setenv("HIDDIFY_MASQUE_DATAGRAM_CEILING_MAX", tc.envValue)
			}
			if got := connectIPDatagramCeilingMax(); got != tc.expectMax {
				t.Fatalf("unexpected ceiling max: got=%d want=%d", got, tc.expectMax)
			}
		})
	}
}

func TestCoreClientFactoryConnectIPDatagramCeilingClamp(t *testing.T) {
	testCases := []struct {
		name            string
		envCeilingMax   string
		requested       uint32
		expectedCeiling int
	}{
		{name: "zero requested uses default ceiling max", envCeilingMax: "4096", requested: 0, expectedCeiling: defaultConnectIPDatagramCeilingMax},
		{name: "zero requested clamps to env max below default", envCeilingMax: "1400", requested: 0, expectedCeiling: 1400},
		{name: "below lower bound clamps to 1280", envCeilingMax: "4096", requested: 1200, expectedCeiling: 1280},
		{name: "within bounds preserved", envCeilingMax: "4096", requested: 1400, expectedCeiling: 1400},
		{name: "above env max clamps down", envCeilingMax: "4096", requested: 5000, expectedCeiling: 4096},
		{name: "default max clamps to 1500", envCeilingMax: "not-a-number", requested: 2000, expectedCeiling: defaultConnectIPDatagramCeilingMax},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("HIDDIFY_MASQUE_DATAGRAM_CEILING_MAX", tc.envCeilingMax)
			session, err := (CoreClientFactory{}).NewSession(context.Background(), ClientOptions{
				Server:                   "example.com",
				ServerPort:               443,
				ConnectIPDatagramCeiling: tc.requested,
			})
			if err != nil {
				t.Fatalf("new core session: %v", err)
			}
			core, ok := session.(*coreSession)
			if !ok {
				t.Fatalf("unexpected session type: %T", session)
			}
			if core.connectIPDatagramCeiling != tc.expectedCeiling {
				t.Fatalf("unexpected connect ip datagram ceiling: got=%d want=%d", core.connectIPDatagramCeiling, tc.expectedCeiling)
			}
		})
	}
}

func TestBuildAndParseIPv4UDPPacket(t *testing.T) {
	src := netip.MustParseAddr("198.18.0.2")
	dst := netip.MustParseAddr("10.200.0.2")
	payload := []byte("hello-masque")
	packet, err := buildIPv4UDPPacket(src, 53000, dst, 5601, payload)
	if err != nil {
		t.Fatalf("build packet: %v", err)
	}
	gotPayload, gotSrc, gotSrcPort, err := parseIPv4UDPPacket(packet)
	if err != nil {
		t.Fatalf("parse packet: %v", err)
	}
	if gotSrc != src {
		t.Fatalf("unexpected src: %s", gotSrc)
	}
	if gotSrcPort != 53000 {
		t.Fatalf("unexpected src port: %d", gotSrcPort)
	}
	if !bytes.Equal(gotPayload, payload) {
		t.Fatalf("unexpected payload: %q", gotPayload)
	}
}

func TestBuildIPv4UDPPacketInplaceReusesBuffer(t *testing.T) {
	src := netip.MustParseAddr("198.18.0.2")
	dst := netip.MustParseAddr("10.200.0.2")
	initial := make([]byte, 0, 2048)
	packetA, err := buildIPv4UDPPacketInplace(initial, src, 53000, dst, 5601, []byte("a"))
	if err != nil {
		t.Fatalf("first packet build: %v", err)
	}
	packetB, err := buildIPv4UDPPacketInplace(packetA[:0], src, 53000, dst, 5601, []byte("bbbb"))
	if err != nil {
		t.Fatalf("second packet build: %v", err)
	}
	if len(packetB) != 32 {
		t.Fatalf("unexpected packet size: got=%d want=32", len(packetB))
	}
	if &packetA[:1][0] != &packetB[:1][0] {
		t.Fatal("expected in-place builder to reuse caller-provided capacity")
	}
}

func TestConnectIPUDPPacketConnWriteTo(t *testing.T) {
	rec := &recordingIPPacketSession{}
	conn := newConnectIPUDPPacketConn(context.Background(), rec)
	n, err := conn.WriteTo([]byte("abc"), &net.UDPAddr{IP: net.ParseIP("10.200.0.2"), Port: 5601})
	if err != nil {
		t.Fatalf("write to: %v", err)
	}
	if n != 3 {
		t.Fatalf("unexpected write n: %d", n)
	}
	if len(rec.lastWrite) == 0 {
		t.Fatal("expected packet write")
	}
	dst := net.IP(rec.lastWrite[16:20]).String()
	if dst != "10.200.0.2" {
		t.Fatalf("unexpected destination ip: %s", dst)
	}
	dstPort := binary.BigEndian.Uint16(rec.lastWrite[22:24])
	if dstPort != 5601 {
		t.Fatalf("unexpected destination port: %d", dstPort)
	}
}

func TestConnectIPUDPPacketConnWriteToRejectsIPv6Destination(t *testing.T) {
	rec := &recordingIPPacketSession{}
	conn := newConnectIPUDPPacketConn(context.Background(), rec)
	_, err := conn.WriteTo([]byte("abc"), &net.UDPAddr{IP: net.ParseIP("2001:db8::2"), Port: 5601})
	if err == nil {
		t.Fatal("expected IPv6 destination rejection for temporary IPv4-only UDP bridge contract")
	}
}

func TestConnectIPUDPPacketConnWriteToSplitsLargePayload(t *testing.T) {
	rec := &recordingIPPacketSession{}
	conn := newConnectIPUDPPacketConn(context.Background(), rec)
	payload := bytes.Repeat([]byte{0xab}, 2500)
	n, err := conn.WriteTo(payload, &net.UDPAddr{IP: net.ParseIP("10.200.0.2"), Port: 5601})
	if err != nil {
		t.Fatalf("write to: %v", err)
	}
	if n != len(payload) {
		t.Fatalf("unexpected write n: got=%d want=%d", n, len(payload))
	}
	if len(rec.writes) != 3 {
		t.Fatalf("unexpected write count: got=%d want=3", len(rec.writes))
	}
	for _, packet := range rec.writes {
		dst := net.IP(packet[16:20]).String()
		if dst != "10.200.0.2" {
			t.Fatalf("unexpected destination ip: %s", dst)
		}
		dstPort := binary.BigEndian.Uint16(packet[22:24])
		if dstPort != 5601 {
			t.Fatalf("unexpected destination port: %d", dstPort)
		}
	}
}

func TestConnectIPUDPPacketConnReadFrom(t *testing.T) {
	packet, err := buildIPv4UDPPacket(
		netip.MustParseAddr("10.200.0.2"),
		5601,
		netip.MustParseAddr("198.18.0.2"),
		53000,
		[]byte("pong"),
	)
	if err != nil {
		t.Fatalf("build packet: %v", err)
	}
	rec := &recordingIPPacketSession{readPacket: packet}
	conn := newConnectIPUDPPacketConn(context.Background(), rec)
	buf := make([]byte, 16)
	n, addr, err := conn.ReadFrom(buf)
	if err != nil {
		t.Fatalf("read from: %v", err)
	}
	if n != 4 || string(buf[:n]) != "pong" {
		t.Fatalf("unexpected payload: %q", buf[:n])
	}
	udpAddr, ok := addr.(*net.UDPAddr)
	if !ok {
		t.Fatalf("unexpected addr type: %T", addr)
	}
	if udpAddr.Port != 5601 || udpAddr.IP.String() != "10.200.0.2" {
		t.Fatalf("unexpected source addr: %v", udpAddr)
	}
}

func TestConnectIPUDPPacketConnReadFromDirectBufferNoStaging(t *testing.T) {
	packet, err := buildIPv4UDPPacket(
		netip.MustParseAddr("10.200.0.2"),
		5601,
		netip.MustParseAddr("198.18.0.2"),
		53000,
		[]byte("pong"),
	)
	if err != nil {
		t.Fatalf("build packet: %v", err)
	}
	rec := &recordingIPPacketSession{readPacket: packet}
	pc := newConnectIPUDPPacketConn(context.Background(), rec)
	c := pc.(*connectIPUDPPacketConn)
	if c.readBuffer != nil {
		t.Fatal("expected lazy read buffer to be unset before first small-buffer read is skipped")
	}
	buf := make([]byte, connectIPUDPDirectReadMin)
	n, addr, err := c.ReadFrom(buf)
	if err != nil {
		t.Fatalf("read from: %v", err)
	}
	if n != 4 || string(buf[:n]) != "pong" {
		t.Fatalf("unexpected payload after in-place shift: %q", buf[:n])
	}
	if c.readBuffer != nil {
		t.Fatal("large-buffer ReadFrom must not allocate conn.readBuffer")
	}
	udpAddr, ok := addr.(*net.UDPAddr)
	if !ok {
		t.Fatalf("unexpected addr type: %T", addr)
	}
	if udpAddr.Port != 5601 || udpAddr.IP.String() != "10.200.0.2" {
		t.Fatalf("unexpected source addr: %v", udpAddr)
	}
}

func TestCoreSessionListenPacketUDPDialDoesNotBlockLifecycleLock(t *testing.T) {
	templateUDP, err := uritemplate.New("https://example.com/masque/udp/{target_host}/{target_port}")
	if err != nil {
		t.Fatalf("build udp template: %v", err)
	}
	dialStarted := make(chan struct{})
	releaseDial := make(chan struct{})
	listenDone := make(chan error, 1)
	var startOnce atomic.Bool
	session := &coreSession{
		options: ClientOptions{
			TransportMode: "connect_udp",
		},
		udpClient:    &qmasque.Client{},
		templateUDP:  templateUDP,
		capabilities: CapabilitySet{ConnectUDP: true, ConnectIP: false},
		udpDial: func(ctx context.Context, client *qmasque.Client, template *uritemplate.Template, target string) (net.PacketConn, error) {
			if startOnce.CompareAndSwap(false, true) {
				close(dialStarted)
			}
			<-releaseDial
			return nil, errors.New("stub dial failure")
		},
	}

	go func() {
		_, listenErr := session.ListenPacket(context.Background(), M.ParseSocksaddrHostPort("127.0.0.1", 5353))
		listenDone <- listenErr
	}()

	select {
	case <-dialStarted:
	case <-time.After(time.Second):
		t.Fatal("listen packet did not reach udp dial hook")
	}

	lifecycleDone := make(chan error, 1)
	go func() {
		_, openErr := session.OpenIPSession(context.Background())
		lifecycleDone <- openErr
	}()

	select {
	case err := <-lifecycleDone:
		if err == nil || !strings.Contains(err.Error(), "does not support CONNECT-IP") {
			t.Fatalf("expected fast CONNECT-IP capability rejection while udp dial is in-flight, got: %v", err)
		}
	case <-time.After(200 * time.Millisecond):
		t.Fatal("OpenIPSession blocked by ListenPacket udp dial lock scope")
	}

	close(releaseDial)
	select {
	case err := <-listenDone:
		if err == nil {
			t.Fatal("expected listen packet error from stub dial failure")
		}
	case <-time.After(time.Second):
		t.Fatal("ListenPacket did not finish after releasing udp dial hook")
	}
}

func TestStreamConnHalfCloseIsolation(t *testing.T) {
	reader := &trackedReadCloser{}
	writer := &trackedWriteCloser{}
	conn := &streamConn{
		reader: reader,
		writer: writer,
	}
	if err := conn.CloseRead(); err != nil {
		t.Fatalf("close read failed: %v", err)
	}
	if reader.closed != 1 {
		t.Fatalf("expected reader to be closed once, got: %d", reader.closed)
	}
	if writer.closed != 0 {
		t.Fatalf("writer should remain open after CloseRead, got closes: %d", writer.closed)
	}
	if err := conn.CloseWrite(); err != nil {
		t.Fatalf("close write failed: %v", err)
	}
	if writer.closed != 1 {
		t.Fatalf("expected writer to be closed once, got: %d", writer.closed)
	}
}

func TestBuildTemplatesRejectsInvalidTCPTemplateURL(t *testing.T) {
	_, _, _, err := buildTemplates(ClientOptions{
		Server:      "example.com",
		ServerPort:  443,
		TemplateTCP: "https://example.com/%zz/{target_host}/{target_port}",
	})
	if err == nil {
		t.Fatal("expected invalid TCP template URL to fail fast")
	}
}

func TestDialContextMasqueOrDirectFallsBackToDirectTCP(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	accepted := make(chan struct{}, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		accepted <- struct{}{}
	}()
	addr := ln.Addr().(*net.TCPAddr)
	dest := M.ParseSocksaddrHostPort("127.0.0.1", uint16(addr.Port))
	session := &coreSession{
		options: ClientOptions{
			Server:           "masque.local",
			ServerPort:       443,
			TemplateTCP:      "https://masque.local/masque/tcp/{target_host}/{target_port}",
			TCPTransport:     "connect_stream",
			TCPMode:          option.MasqueTCPModeMasqueOrDirect,
			FallbackPolicy:   option.MasqueFallbackPolicyDirectExplicit,
		},
		capabilities: CapabilitySet{ConnectTCP: true},
		tcpRoundTripper: roundTripperFunc(func(req *http.Request) (*http.Response, error) {
			return nil, errors.New("stub masque connect_stream unavailable")
		}),
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := session.DialContext(ctx, "tcp", dest)
	if err != nil {
		t.Fatalf("DialContext: %v", err)
	}
	defer conn.Close()
	select {
	case <-accepted:
	case <-time.After(2 * time.Second):
		t.Fatal("expected direct TCP accept after MASQUE failure")
	}
}

func TestDialContextMasqueOrDirectDoesNotFallbackOnAuth(t *testing.T) {
	dest := M.ParseSocksaddrHostPort("127.0.0.1", 9)
	session := &coreSession{
		options: ClientOptions{
			Server:           "masque.local",
			ServerPort:       443,
			TemplateTCP:      "https://masque.local/masque/tcp/{target_host}/{target_port}",
			TCPTransport:     "connect_stream",
			TCPMode:          option.MasqueTCPModeMasqueOrDirect,
			FallbackPolicy:   option.MasqueFallbackPolicyDirectExplicit,
		},
		capabilities: CapabilitySet{ConnectTCP: true},
		tcpRoundTripper: roundTripperFunc(func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusForbidden,
				Body:       io.NopCloser(bytes.NewReader(nil)),
			}, nil
		}),
	}
	_, err := session.DialContext(context.Background(), "tcp", dest)
	if !errors.Is(err, ErrAuthFailed) {
		t.Fatalf("expected ErrAuthFailed without direct fallback, got: %v", err)
	}
}

func TestDialContextStrictMasqueDoesNotFallbackToDirect(t *testing.T) {
	dest := M.ParseSocksaddrHostPort("127.0.0.1", 9)
	session := &coreSession{
		options: ClientOptions{
			Server:        "masque.local",
			ServerPort:    443,
			TemplateTCP:   "https://masque.local/masque/tcp/{target_host}/{target_port}",
			TCPTransport:  "connect_stream",
			TCPMode:       option.MasqueTCPModeStrictMasque,
			FallbackPolicy: option.MasqueFallbackPolicyStrict,
		},
		capabilities: CapabilitySet{ConnectTCP: true},
		tcpRoundTripper: roundTripperFunc(func(req *http.Request) (*http.Response, error) {
			return nil, errors.New("stub masque connect_stream unavailable")
		}),
	}
	_, err := session.DialContext(context.Background(), "tcp", dest)
	if !errors.Is(err, ErrTCPConnectStreamFailed) {
		t.Fatalf("expected ErrTCPConnectStreamFailed, got: %v", err)
	}
}

func TestDialTCPStreamAuthAndPolicyStatusesMapToAuthClass(t *testing.T) {
	for _, statusCode := range []int{http.StatusUnauthorized, http.StatusForbidden} {
		t.Run(http.StatusText(statusCode), func(t *testing.T) {
			session := &coreSession{
				options: ClientOptions{
					Server:      "masque.local",
					ServerPort:  443,
					TemplateTCP: "https://masque.local/masque/tcp/{target_host}/{target_port}",
				},
				tcpRoundTripper: roundTripperFunc(func(req *http.Request) (*http.Response, error) {
					if req.Method != http.MethodConnect {
						t.Fatalf("unexpected method: %s", req.Method)
					}
					return &http.Response{
						StatusCode: statusCode,
						Body:       io.NopCloser(bytes.NewReader(nil)),
					}, nil
				}),
			}
			_, err := session.dialTCPStream(context.Background(), M.ParseSocksaddrHostPort("example.com", 443))
			if !errors.Is(err, ErrAuthFailed) {
				t.Fatalf("expected ErrAuthFailed for status=%d, got: %v", statusCode, err)
			}
			if got := ClassifyError(err); got != ErrorClassAuth {
				t.Fatalf("expected auth class for status=%d, got: %s", statusCode, got)
			}
		})
	}
}

func TestDialTCPStreamNonAuthStatusMapsToDialClass(t *testing.T) {
	for _, statusCode := range []int{
		http.StatusTooManyRequests,
		http.StatusBadGateway,
		http.StatusServiceUnavailable,
	} {
		t.Run(http.StatusText(statusCode), func(t *testing.T) {
			session := &coreSession{
				options: ClientOptions{
					Server:      "masque.local",
					ServerPort:  443,
					TemplateTCP: "https://masque.local/masque/tcp/{target_host}/{target_port}",
				},
				tcpRoundTripper: roundTripperFunc(func(req *http.Request) (*http.Response, error) {
					return &http.Response{
						StatusCode: statusCode,
						Body:       io.NopCloser(bytes.NewReader(nil)),
					}, nil
				}),
			}
			_, err := session.dialTCPStream(context.Background(), M.ParseSocksaddrHostPort("example.com", 443))
			if !errors.Is(err, ErrTCPConnectStreamFailed) {
				t.Fatalf("expected ErrTCPConnectStreamFailed for non-auth non-2xx status=%d, got: %v", statusCode, err)
			}
			if got := ClassifyError(err); got != ErrorClassDial {
				t.Fatalf("expected dial class for non-auth non-2xx status=%d, got: %s", statusCode, got)
			}
		})
	}
}

func TestDialTCPStreamRetryableRoundTripErrorsKeepDialClassAndBudget(t *testing.T) {
	retryableErrors := map[string]error{
		"timeout_while_connecting":      timeoutNetError{msg: "timeout while connecting"},
		"no_recent_network_activity":   &quic.IdleTimeoutError{},
		"idle_timeout_reached":         timeoutNetError{msg: "idle timeout reached"},
		"application_error_0x100":      &quic.ApplicationError{ErrorCode: 0x100, Remote: true},
	}
	for name, retryErr := range retryableErrors {
		t.Run(name, func(t *testing.T) {
			attempts := 0
			session := &coreSession{
				options: ClientOptions{
					Server:      "masque.local",
					ServerPort:  443,
					TemplateTCP: "https://masque.local/masque/tcp/{target_host}/{target_port}",
				},
				tcpRoundTripper: roundTripperFunc(func(req *http.Request) (*http.Response, error) {
					attempts++
					return nil, retryErr
				}),
			}
			_, err := session.dialTCPStream(context.Background(), M.ParseSocksaddrHostPort("example.com", 443))
			if !errors.Is(err, ErrTCPConnectStreamFailed) {
				t.Fatalf("expected ErrTCPConnectStreamFailed, got: %v", err)
			}
			if got := ClassifyError(err); got != ErrorClassDial {
				t.Fatalf("expected dial class for retryable roundtrip error, got: %s", got)
			}
			if attempts != 3 {
				t.Fatalf("expected deterministic retry budget attempts=3, got: %d", attempts)
			}
		})
	}
}

func TestDialTCPStreamRetryExhaustedPreservesLastRoundTripCause(t *testing.T) {
	retryErr := timeoutNetError{msg: "timeout while connecting"}
	attempts := 0
	session := &coreSession{
		options: ClientOptions{
			Server:      "masque.local",
			ServerPort:  443,
			TemplateTCP: "https://masque.local/masque/tcp/{target_host}/{target_port}",
		},
		tcpRoundTripper: roundTripperFunc(func(req *http.Request) (*http.Response, error) {
			attempts++
			return nil, retryErr
		}),
	}
	_, err := session.dialTCPStream(context.Background(), M.ParseSocksaddrHostPort("example.com", 443))
	if !errors.Is(err, ErrTCPConnectStreamFailed) {
		t.Fatalf("expected ErrTCPConnectStreamFailed, got: %v", err)
	}
	if !errors.Is(err, retryErr) {
		t.Fatalf("expected retry-exhausted error to preserve the last roundtrip cause, got: %v", err)
	}
	if got := ClassifyError(err); got != ErrorClassDial {
		t.Fatalf("expected dial class for retry-exhausted roundtrip error, got: %s", got)
	}
	if attempts != 3 {
		t.Fatalf("expected deterministic retry budget attempts=3, got: %d", attempts)
	}
}

func TestDialTCPStreamNonRetryableRoundTripErrorDoesNotRetryAndKeepsDialClass(t *testing.T) {
	attempts := 0
	nonRetryableErr := errors.New("tls: bad certificate")
	session := &coreSession{
		options: ClientOptions{
			Server:      "masque.local",
			ServerPort:  443,
			TemplateTCP: "https://masque.local/masque/tcp/{target_host}/{target_port}",
		},
		tcpRoundTripper: roundTripperFunc(func(req *http.Request) (*http.Response, error) {
			attempts++
			return nil, nonRetryableErr
		}),
	}
	_, err := session.dialTCPStream(context.Background(), M.ParseSocksaddrHostPort("example.com", 443))
	if !errors.Is(err, ErrTCPConnectStreamFailed) {
		t.Fatalf("expected ErrTCPConnectStreamFailed, got: %v", err)
	}
	if !errors.Is(err, nonRetryableErr) {
		t.Fatalf("expected non-retryable roundtrip error to preserve cause, got: %v", err)
	}
	if got := ClassifyError(err); got != ErrorClassDial {
		t.Fatalf("expected dial class for non-retryable roundtrip error, got: %s", got)
	}
	if attempts != 1 {
		t.Fatalf("expected no retries for non-retryable roundtrip error (attempts=1), got: %d", attempts)
	}
}

func TestDialTCPStreamContextCancelDuringRetryBackoffStopsFurtherAttempts(t *testing.T) {
	attempts := 0
	ctx, cancel := context.WithCancel(context.Background())
	firstAttempt := make(chan struct{}, 1)
	go func() {
		<-firstAttempt
		time.Sleep(5 * time.Millisecond)
		cancel()
	}()
	session := &coreSession{
		options: ClientOptions{
			Server:      "masque.local",
			ServerPort:  443,
			TemplateTCP: "https://masque.local/masque/tcp/{target_host}/{target_port}",
		},
		tcpRoundTripper: roundTripperFunc(func(req *http.Request) (*http.Response, error) {
			attempts++
			if attempts == 1 {
				firstAttempt <- struct{}{}
			}
			return nil, timeoutNetError{msg: "timeout while connecting"}
		}),
	}
	_, err := session.dialTCPStream(ctx, M.ParseSocksaddrHostPort("example.com", 443))
	if !errors.Is(err, ErrTCPConnectStreamFailed) {
		t.Fatalf("expected ErrTCPConnectStreamFailed, got: %v", err)
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context cancellation cause to be preserved, got: %v", err)
	}
	if got := ClassifyError(err); got != ErrorClassDial {
		t.Fatalf("expected dial class when retry loop is cancelled during backoff, got: %s", got)
	}
	if attempts != 1 {
		t.Fatalf("expected cancellation during backoff to stop retries (attempts=1), got: %d", attempts)
	}
}

func TestDialTCPStreamContextCanceledBeforeFirstRoundTripStopsWithoutAttempt(t *testing.T) {
	attempts := 0
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	session := &coreSession{
		options: ClientOptions{
			Server:      "masque.local",
			ServerPort:  443,
			TemplateTCP: "https://masque.local/masque/tcp/{target_host}/{target_port}",
		},
		tcpRoundTripper: roundTripperFunc(func(req *http.Request) (*http.Response, error) {
			attempts++
			return nil, timeoutNetError{msg: "timeout while connecting"}
		}),
	}
	_, err := session.dialTCPStream(ctx, M.ParseSocksaddrHostPort("example.com", 443))
	if !errors.Is(err, ErrTCPConnectStreamFailed) {
		t.Fatalf("expected ErrTCPConnectStreamFailed, got: %v", err)
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context cancellation cause to be preserved, got: %v", err)
	}
	if got := ClassifyError(err); got != ErrorClassDial {
		t.Fatalf("expected dial class for cancel-before-roundtrip path, got: %s", got)
	}
	if attempts != 0 {
		t.Fatalf("expected no RoundTrip attempt when context is canceled before dial loop, got attempts=%d", attempts)
	}
}

func TestDialTCPStreamContextDeadlineExceededBeforeFirstRoundTripStopsWithoutAttempt(t *testing.T) {
	attempts := 0
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	session := &coreSession{
		options: ClientOptions{
			Server:      "masque.local",
			ServerPort:  443,
			TemplateTCP: "https://masque.local/masque/tcp/{target_host}/{target_port}",
		},
		tcpRoundTripper: roundTripperFunc(func(req *http.Request) (*http.Response, error) {
			attempts++
			return nil, timeoutNetError{msg: "timeout while connecting"}
		}),
	}
	_, err := session.dialTCPStream(ctx, M.ParseSocksaddrHostPort("example.com", 443))
	if !errors.Is(err, ErrTCPConnectStreamFailed) {
		t.Fatalf("expected ErrTCPConnectStreamFailed, got: %v", err)
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected deadline exceeded cause to be preserved, got: %v", err)
	}
	if got := ClassifyError(err); got != ErrorClassDial {
		t.Fatalf("expected dial class for deadline-before-roundtrip path, got: %s", got)
	}
	if attempts != 0 {
		t.Fatalf("expected no RoundTrip attempt when deadline is exceeded before dial loop, got attempts=%d", attempts)
	}
}

func TestDialTCPStreamContextDeadlineExceededDuringRetryBackoffStopsFurtherAttempts(t *testing.T) {
	attempts := 0
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	session := &coreSession{
		options: ClientOptions{
			Server:      "masque.local",
			ServerPort:  443,
			TemplateTCP: "https://masque.local/masque/tcp/{target_host}/{target_port}",
		},
		tcpRoundTripper: roundTripperFunc(func(req *http.Request) (*http.Response, error) {
			attempts++
			return nil, timeoutNetError{msg: "timeout while connecting"}
		}),
	}
	_, err := session.dialTCPStream(ctx, M.ParseSocksaddrHostPort("example.com", 443))
	if !errors.Is(err, ErrTCPConnectStreamFailed) {
		t.Fatalf("expected ErrTCPConnectStreamFailed, got: %v", err)
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected deadline exceeded cause to be preserved, got: %v", err)
	}
	if got := ClassifyError(err); got != ErrorClassDial {
		t.Fatalf("expected dial class when retry loop is stopped by deadline during backoff, got: %s", got)
	}
	if attempts != 1 {
		t.Fatalf("expected deadline during backoff to stop retries after first attempt (attempts=1), got: %d", attempts)
	}
}

func TestDialTCPStreamContextCanceledRoundTripPreservesCauseWithoutRetry(t *testing.T) {
	attempts := 0
	session := &coreSession{
		options: ClientOptions{
			Server:      "masque.local",
			ServerPort:  443,
			TemplateTCP: "https://masque.local/masque/tcp/{target_host}/{target_port}",
		},
		tcpRoundTripper: roundTripperFunc(func(req *http.Request) (*http.Response, error) {
			attempts++
			return nil, context.Canceled
		}),
	}
	_, err := session.dialTCPStream(context.Background(), M.ParseSocksaddrHostPort("example.com", 443))
	if !errors.Is(err, ErrTCPConnectStreamFailed) {
		t.Fatalf("expected ErrTCPConnectStreamFailed, got: %v", err)
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context cancellation cause to be preserved, got: %v", err)
	}
	if got := ClassifyError(err); got != ErrorClassDial {
		t.Fatalf("expected dial class for roundtrip context cancellation, got: %s", got)
	}
	if attempts != 1 {
		t.Fatalf("expected no retries for roundtrip context cancellation, got attempts=%d", attempts)
	}
}

func TestDialTCPStreamContextDeadlineExceededRoundTripPreservesCauseWithoutRetry(t *testing.T) {
	attempts := 0
	session := &coreSession{
		options: ClientOptions{
			Server:      "masque.local",
			ServerPort:  443,
			TemplateTCP: "https://masque.local/masque/tcp/{target_host}/{target_port}",
		},
		tcpRoundTripper: roundTripperFunc(func(req *http.Request) (*http.Response, error) {
			attempts++
			return nil, context.DeadlineExceeded
		}),
	}
	_, err := session.dialTCPStream(context.Background(), M.ParseSocksaddrHostPort("example.com", 443))
	if !errors.Is(err, ErrTCPConnectStreamFailed) {
		t.Fatalf("expected ErrTCPConnectStreamFailed, got: %v", err)
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected context deadline cause to be preserved, got: %v", err)
	}
	if got := ClassifyError(err); got != ErrorClassDial {
		t.Fatalf("expected dial class for roundtrip deadline, got: %s", got)
	}
	if attempts != 1 {
		t.Fatalf("expected no retries for roundtrip deadline, got attempts=%d", attempts)
	}
}

func TestDialTCPStreamRelayPhaseDeadlineExceededMapsToDialClass(t *testing.T) {
	session := &coreSession{
		options: ClientOptions{
			Server:      "masque.local",
			ServerPort:  443,
			TemplateTCP: "https://masque.local/masque/tcp/{target_host}/{target_port}",
		},
		tcpRoundTripper: roundTripperFunc(func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       &contextBoundReadCloser{ctx: req.Context()},
			}, nil
		}),
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Millisecond)
	defer cancel()
	conn, err := session.dialTCPStream(ctx, M.ParseSocksaddrHostPort("example.com", 443))
	if err != nil {
		t.Fatalf("dial should succeed before relay-phase deadline, got: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	time.Sleep(25 * time.Millisecond)
	buf := make([]byte, 8)
	_, err = conn.Read(buf)
	if !errors.Is(err, ErrTCPConnectStreamFailed) {
		t.Fatalf("expected relay-phase read error to preserve ErrTCPConnectStreamFailed, got: %v", err)
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected relay-phase read error to preserve context deadline cause, got: %v", err)
	}
	if got := ClassifyError(err); got != ErrorClassDial {
		t.Fatalf("expected relay-phase deadline to classify as dial, got: %s", got)
	}
}

func TestDialTCPStreamInProcessHTTP3ProxySuccess(t *testing.T) {
	targetListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen tcp target: %v", err)
	}
	t.Cleanup(func() { _ = targetListener.Close() })
	go func() {
		conn, acceptErr := targetListener.Accept()
		if acceptErr != nil {
			return
		}
		defer conn.Close()
		buf := make([]byte, 64)
		n, readErr := conn.Read(buf)
		if readErr != nil {
			return
		}
		if string(buf[:n]) != "ping" {
			return
		}
		_, _ = conn.Write([]byte("pong"))
	}()

	proxyPort := startInProcessTCPConnectProxy(t, func(targetHost, targetPort string, r *http.Request, w http.ResponseWriter) {
		if targetHost != "127.0.0.1" || targetPort != strconv.Itoa(targetListener.Addr().(*net.TCPAddr).Port) {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		upstream, dialErr := net.DialTimeout("tcp", net.JoinHostPort(targetHost, targetPort), 2*time.Second)
		if dialErr != nil {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		defer upstream.Close()
		_ = upstream.SetDeadline(time.Now().Add(3 * time.Second))
		w.WriteHeader(http.StatusOK)
		if flusher, ok := w.(http.Flusher); ok {
			flusher.Flush()
		}
		copyDone := make(chan struct{}, 1)
		go func() {
			_, _ = io.Copy(upstream, r.Body)
			if tcpConn, ok := upstream.(*net.TCPConn); ok {
				_ = tcpConn.CloseWrite()
			}
			copyDone <- struct{}{}
		}()
		_, _ = io.Copy(w, upstream)
		<-copyDone
	})
	waitCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	session, err := (CoreClientFactory{}).NewSession(waitCtx, ClientOptions{
		Server:     "127.0.0.1",
		ServerPort: uint16(proxyPort),
		Insecure:   true,
		TCPTransport: "connect_stream",
	})
	if err != nil {
		t.Fatalf("new session: %v", err)
	}
	t.Cleanup(func() { _ = session.Close() })

	conn, err := session.DialContext(waitCtx, "tcp", M.ParseSocksaddrHostPort("127.0.0.1", uint16(targetListener.Addr().(*net.TCPAddr).Port)))
	if err != nil {
		t.Fatalf("dial tcp stream over in-process http3 failed: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatalf("write tunnel payload: %v", err)
	}
	reply := make([]byte, 8)
	n, err := conn.Read(reply)
	if err != nil {
		t.Fatalf("read tunnel payload: %v", err)
	}
	if got := string(reply[:n]); got != "pong" {
		t.Fatalf("unexpected relay response: %q", got)
	}
}

func TestDialTCPStreamInProcessHTTP3ProxyAuthAndPolicyStatusesMapToAuthClass(t *testing.T) {
	for _, statusCode := range []int{http.StatusUnauthorized, http.StatusForbidden} {
		t.Run(http.StatusText(statusCode), func(t *testing.T) {
			proxyPort := startInProcessTCPConnectProxy(t, func(targetHost, targetPort string, r *http.Request, w http.ResponseWriter) {
				w.WriteHeader(statusCode)
			})
			waitCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			session, err := (CoreClientFactory{}).NewSession(waitCtx, ClientOptions{
				Server:       "127.0.0.1",
				ServerPort:   uint16(proxyPort),
				Insecure:     true,
				TCPTransport: "connect_stream",
			})
			if err != nil {
				t.Fatalf("new session: %v", err)
			}
			t.Cleanup(func() { _ = session.Close() })

			_, err = session.DialContext(waitCtx, "tcp", M.ParseSocksaddrHostPort("127.0.0.1", 443))
			if !errors.Is(err, ErrAuthFailed) {
				t.Fatalf("expected ErrAuthFailed for status=%d, got: %v", statusCode, err)
			}
			if got := ClassifyError(err); got != ErrorClassAuth {
				t.Fatalf("expected auth class for status=%d, got: %s", statusCode, got)
			}
		})
	}
}

func TestDialTCPStreamInProcessHTTP3ProxyNonAuthStatusMapsToDialClass(t *testing.T) {
	for _, statusCode := range []int{
		http.StatusTooManyRequests,
		http.StatusBadGateway,
		http.StatusServiceUnavailable,
	} {
		t.Run(http.StatusText(statusCode), func(t *testing.T) {
			proxyPort := startInProcessTCPConnectProxy(t, func(targetHost, targetPort string, r *http.Request, w http.ResponseWriter) {
				w.WriteHeader(statusCode)
			})
			waitCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			session, err := (CoreClientFactory{}).NewSession(waitCtx, ClientOptions{
				Server:       "127.0.0.1",
				ServerPort:   uint16(proxyPort),
				Insecure:     true,
				TCPTransport: "connect_stream",
			})
			if err != nil {
				t.Fatalf("new session: %v", err)
			}
			t.Cleanup(func() { _ = session.Close() })

			_, err = session.DialContext(waitCtx, "tcp", M.ParseSocksaddrHostPort("127.0.0.1", 443))
			if !errors.Is(err, ErrTCPConnectStreamFailed) {
				t.Fatalf("expected ErrTCPConnectStreamFailed for non-auth status=%d, got: %v", statusCode, err)
			}
			if got := ClassifyError(err); got != ErrorClassDial {
				t.Fatalf("expected dial class for non-auth status=%d, got: %s", statusCode, got)
			}
		})
	}
}

func TestDialTCPStreamInProcessHTTP3ProxyRelayPhaseDeadlineExceededMapsToDialClass(t *testing.T) {
	proxyPort := startInProcessTCPConnectProxy(t, func(targetHost, targetPort string, r *http.Request, w http.ResponseWriter) {
		w.WriteHeader(http.StatusOK)
		if flusher, ok := w.(http.Flusher); ok {
			flusher.Flush()
		}
		<-r.Context().Done()
	})
	waitCtx, waitCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer waitCancel()
	session, err := (CoreClientFactory{}).NewSession(waitCtx, ClientOptions{
		Server:       "127.0.0.1",
		ServerPort:   uint16(proxyPort),
		Insecure:     true,
		TCPTransport: "connect_stream",
	})
	if err != nil {
		t.Fatalf("new session: %v", err)
	}
	t.Cleanup(func() { _ = session.Close() })

	relayCtx, relayCancel := context.WithTimeout(context.Background(), 40*time.Millisecond)
	defer relayCancel()
	conn, err := session.DialContext(relayCtx, "tcp", M.ParseSocksaddrHostPort("127.0.0.1", 443))
	if err != nil {
		t.Fatalf("dial should succeed before relay-phase deadline, got: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	buf := make([]byte, 8)
	_, err = conn.Read(buf)
	if !errors.Is(err, ErrTCPConnectStreamFailed) {
		t.Fatalf("expected relay-phase read error to preserve ErrTCPConnectStreamFailed, got: %v", err)
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected relay-phase read error to preserve context deadline cause, got: %v", err)
	}
	if got := ClassifyError(err); got != ErrorClassDial {
		t.Fatalf("expected relay-phase deadline to classify as dial, got: %s", got)
	}
}

func TestDialTCPStreamInProcessHTTP3ProxyRelayPhaseCanceledMapsToDialClass(t *testing.T) {
	proxyPort := startInProcessTCPConnectProxy(t, func(targetHost, targetPort string, r *http.Request, w http.ResponseWriter) {
		w.WriteHeader(http.StatusOK)
		if flusher, ok := w.(http.Flusher); ok {
			flusher.Flush()
		}
		<-r.Context().Done()
	})
	waitCtx, waitCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer waitCancel()
	session, err := (CoreClientFactory{}).NewSession(waitCtx, ClientOptions{
		Server:       "127.0.0.1",
		ServerPort:   uint16(proxyPort),
		Insecure:     true,
		TCPTransport: "connect_stream",
	})
	if err != nil {
		t.Fatalf("new session: %v", err)
	}
	t.Cleanup(func() { _ = session.Close() })

	relayCtx, relayCancel := context.WithCancel(context.Background())
	conn, err := session.DialContext(relayCtx, "tcp", M.ParseSocksaddrHostPort("127.0.0.1", 443))
	if err != nil {
		t.Fatalf("dial should succeed before relay-phase cancel, got: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	relayCancel()

	buf := make([]byte, 8)
	_, err = conn.Read(buf)
	if !errors.Is(err, ErrTCPConnectStreamFailed) {
		t.Fatalf("expected relay-phase read error to preserve ErrTCPConnectStreamFailed, got: %v", err)
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected relay-phase read error to preserve context cancel cause, got: %v", err)
	}
	if got := ClassifyError(err); got != ErrorClassDial {
		t.Fatalf("expected relay-phase cancel to classify as dial, got: %s", got)
	}
}

func TestDialTCPStreamInProcessHTTP3ProxyRetryableRoundTripErrorKeepsBudgetAndDialClass(t *testing.T) {
	proxyPort := startInProcessTCPConnectProxy(t, func(targetHost, targetPort string, r *http.Request, w http.ResponseWriter) {
		w.WriteHeader(http.StatusOK)
		if flusher, ok := w.(http.Flusher); ok {
			flusher.Flush()
		}
		<-r.Context().Done()
	})
	waitCtx, waitCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer waitCancel()
	var attempts int32
	retryableErr := timeoutNetError{msg: "timeout during quic dial"}
	session, err := (CoreClientFactory{}).NewSession(waitCtx, ClientOptions{
		Server:       "127.0.0.1",
		ServerPort:   uint16(proxyPort),
		Insecure:     true,
		TCPTransport: "connect_stream",
		QUICDial: func(ctx context.Context, addr string, tlsCfg *tls.Config, cfg *quic.Config) (*quic.Conn, error) {
			if atomic.AddInt32(&attempts, 1) < 3 {
				return nil, retryableErr
			}
			return quic.DialAddr(ctx, addr, tlsCfg, cfg)
		},
	})
	if err != nil {
		t.Fatalf("new session: %v", err)
	}
	t.Cleanup(func() { _ = session.Close() })

	conn, err := session.DialContext(waitCtx, "tcp", M.ParseSocksaddrHostPort("127.0.0.1", 443))
	if err != nil {
		t.Fatalf("expected dial success after retryable roundtrip errors, got: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if got := atomic.LoadInt32(&attempts); got != 3 {
		t.Fatalf("expected deterministic retry budget attempts=3 before success, got: %d", got)
	}
}

func TestDialTCPStreamInProcessHTTP3ProxyRetryableApplicationErrorKeepsBudgetAndDialClass(t *testing.T) {
	proxyPort := startInProcessTCPConnectProxy(t, func(targetHost, targetPort string, r *http.Request, w http.ResponseWriter) {
		w.WriteHeader(http.StatusOK)
		if flusher, ok := w.(http.Flusher); ok {
			flusher.Flush()
		}
		<-r.Context().Done()
	})
	waitCtx, waitCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer waitCancel()
	var attempts int32
	retryableErr := &quic.ApplicationError{ErrorCode: 0x100, Remote: true}
	session, err := (CoreClientFactory{}).NewSession(waitCtx, ClientOptions{
		Server:       "127.0.0.1",
		ServerPort:   uint16(proxyPort),
		Insecure:     true,
		TCPTransport: "connect_stream",
		QUICDial: func(ctx context.Context, addr string, tlsCfg *tls.Config, cfg *quic.Config) (*quic.Conn, error) {
			if atomic.AddInt32(&attempts, 1) < 3 {
				return nil, retryableErr
			}
			return quic.DialAddr(ctx, addr, tlsCfg, cfg)
		},
	})
	if err != nil {
		t.Fatalf("new session: %v", err)
	}
	t.Cleanup(func() { _ = session.Close() })

	conn, err := session.DialContext(waitCtx, "tcp", M.ParseSocksaddrHostPort("127.0.0.1", 443))
	if err != nil {
		t.Fatalf("expected dial success after retryable application errors, got: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if got := atomic.LoadInt32(&attempts); got != 3 {
		t.Fatalf("expected deterministic retry budget attempts=3 before success, got: %d", got)
	}
}

func TestValidateQUICTransportPacketConnTierAUDPConnPasses(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen packet: %v", err)
	}
	defer pc.Close()
	t.Setenv("MASQUE_QUIC_PACKET_CONN_POLICY", "strict")
	if err := ValidateQUICTransportPacketConn(pc, "test_server"); err != nil {
		t.Fatalf("expected TierA udp conn to pass strict policy, got: %v", err)
	}
}

func TestValidateQUICTransportPacketConnTierBStrictRejects(t *testing.T) {
	t.Setenv("MASQUE_QUIC_PACKET_CONN_POLICY", "strict")
	pc := &tierBPacketConnStub{}
	err := ValidateQUICTransportPacketConn(pc, "test_custom")
	if err == nil {
		t.Fatal("expected strict policy to reject TierB packet conn")
	}
	if !errors.Is(err, ErrQUICPacketConnContract) {
		t.Fatalf("expected ErrQUICPacketConnContract, got: %v", err)
	}
}

func TestCustomQUICDialStrictPolicyRejects(t *testing.T) {
	t.Setenv("MASQUE_QUIC_PACKET_CONN_POLICY", "strict")
	session := &coreSession{
		options: ClientOptions{
			QUICDial: func(ctx context.Context, addr string, tlsCfg *tls.Config, cfg *quic.Config) (*quic.Conn, error) {
				t.Fatal("custom QUICDial must not run in strict mode")
				return nil, nil
			},
		},
	}
	_, err := session.quicDialWithPolicy("client_connect_stream")(context.Background(), "127.0.0.1:443", &tls.Config{}, &quic.Config{})
	if err == nil {
		t.Fatal("expected strict policy reject error")
	}
	if !errors.Is(err, ErrQUICPacketConnContract) {
		t.Fatalf("expected ErrQUICPacketConnContract, got: %v", err)
	}
}

type tierBPacketConnStub struct{}

func (s *tierBPacketConnStub) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	return 0, &net.UDPAddr{}, io.EOF
}
func (s *tierBPacketConnStub) WriteTo(p []byte, addr net.Addr) (n int, err error) { return len(p), nil }
func (s *tierBPacketConnStub) Close() error                                        { return nil }
func (s *tierBPacketConnStub) LocalAddr() net.Addr                                 { return &net.UDPAddr{} }
func (s *tierBPacketConnStub) SetDeadline(t time.Time) error                       { return nil }
func (s *tierBPacketConnStub) SetReadDeadline(t time.Time) error                   { return nil }
func (s *tierBPacketConnStub) SetWriteDeadline(t time.Time) error                  { return nil }

func TestDialTCPStreamInProcessHTTP3ProxyRetryableIdleAndNoRecentNetworkActivityKeepsBudgetAndDialClass(t *testing.T) {
	retryableErrors := map[string]error{
		"idle_timeout_reached":       timeoutNetError{msg: "idle timeout reached"},
		"no_recent_network_activity": &quic.IdleTimeoutError{},
	}
	for name, retryableErr := range retryableErrors {
		t.Run(name, func(t *testing.T) {
			proxyPort := startInProcessTCPConnectProxy(t, func(targetHost, targetPort string, r *http.Request, w http.ResponseWriter) {
				w.WriteHeader(http.StatusOK)
				if flusher, ok := w.(http.Flusher); ok {
					flusher.Flush()
				}
				<-r.Context().Done()
			})
			waitCtx, waitCancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer waitCancel()
			var attempts int32
			session, err := (CoreClientFactory{}).NewSession(waitCtx, ClientOptions{
				Server:       "127.0.0.1",
				ServerPort:   uint16(proxyPort),
				Insecure:     true,
				TCPTransport: "connect_stream",
				QUICDial: func(ctx context.Context, addr string, tlsCfg *tls.Config, cfg *quic.Config) (*quic.Conn, error) {
					if atomic.AddInt32(&attempts, 1) < 3 {
						return nil, retryableErr
					}
					return quic.DialAddr(ctx, addr, tlsCfg, cfg)
				},
			})
			if err != nil {
				t.Fatalf("new session: %v", err)
			}
			t.Cleanup(func() { _ = session.Close() })

			conn, err := session.DialContext(waitCtx, "tcp", M.ParseSocksaddrHostPort("127.0.0.1", 443))
			if err != nil {
				t.Fatalf("expected dial success after retryable roundtrip errors, got: %v", err)
			}
			t.Cleanup(func() { _ = conn.Close() })
			if got := atomic.LoadInt32(&attempts); got != 3 {
				t.Fatalf("expected deterministic retry budget attempts=3 before success, got: %d", got)
			}
		})
	}
}

func TestDialTCPStreamInProcessHTTP3ProxyRelayPhaseWriteDeadlineExceededMapsToDialClass(t *testing.T) {
	proxyPort := startInProcessTCPConnectProxy(t, func(targetHost, targetPort string, r *http.Request, w http.ResponseWriter) {
		w.WriteHeader(http.StatusOK)
		if flusher, ok := w.(http.Flusher); ok {
			flusher.Flush()
		}
		<-r.Context().Done()
	})
	waitCtx, waitCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer waitCancel()
	session, err := (CoreClientFactory{}).NewSession(waitCtx, ClientOptions{
		Server:       "127.0.0.1",
		ServerPort:   uint16(proxyPort),
		Insecure:     true,
		TCPTransport: "connect_stream",
	})
	if err != nil {
		t.Fatalf("new session: %v", err)
	}
	t.Cleanup(func() { _ = session.Close() })

	relayCtx, relayCancel := context.WithTimeout(context.Background(), 40*time.Millisecond)
	defer relayCancel()
	conn, err := session.DialContext(relayCtx, "tcp", M.ParseSocksaddrHostPort("127.0.0.1", 443))
	if err != nil {
		t.Fatalf("dial should succeed before relay-phase deadline, got: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	time.Sleep(70 * time.Millisecond)

	writeErr := awaitWriteError(conn, 2*time.Second)
	if !errors.Is(writeErr, ErrTCPConnectStreamFailed) {
		t.Fatalf("expected relay-phase write error to preserve ErrTCPConnectStreamFailed, got: %v", writeErr)
	}
	if !errors.Is(writeErr, context.DeadlineExceeded) {
		t.Fatalf("expected relay-phase write error to preserve context deadline cause, got: %v", writeErr)
	}
	if got := ClassifyError(writeErr); got != ErrorClassDial {
		t.Fatalf("expected relay-phase write deadline to classify as dial, got: %s", got)
	}
}

func TestDialTCPStreamInProcessHTTP3ProxyRelayPhaseWriteCanceledMapsToDialClass(t *testing.T) {
	proxyPort := startInProcessTCPConnectProxy(t, func(targetHost, targetPort string, r *http.Request, w http.ResponseWriter) {
		w.WriteHeader(http.StatusOK)
		if flusher, ok := w.(http.Flusher); ok {
			flusher.Flush()
		}
		<-r.Context().Done()
	})
	waitCtx, waitCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer waitCancel()
	session, err := (CoreClientFactory{}).NewSession(waitCtx, ClientOptions{
		Server:       "127.0.0.1",
		ServerPort:   uint16(proxyPort),
		Insecure:     true,
		TCPTransport: "connect_stream",
	})
	if err != nil {
		t.Fatalf("new session: %v", err)
	}
	t.Cleanup(func() { _ = session.Close() })

	relayCtx, relayCancel := context.WithCancel(context.Background())
	conn, err := session.DialContext(relayCtx, "tcp", M.ParseSocksaddrHostPort("127.0.0.1", 443))
	if err != nil {
		t.Fatalf("dial should succeed before relay-phase cancel, got: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	relayCancel()

	writeErr := awaitWriteError(conn, 2*time.Second)
	if !errors.Is(writeErr, ErrTCPConnectStreamFailed) {
		t.Fatalf("expected relay-phase write error to preserve ErrTCPConnectStreamFailed, got: %v", writeErr)
	}
	if !errors.Is(writeErr, context.Canceled) {
		t.Fatalf("expected relay-phase write error to preserve context cancel cause, got: %v", writeErr)
	}
	if got := ClassifyError(writeErr); got != ErrorClassDial {
		t.Fatalf("expected relay-phase write cancel to classify as dial, got: %s", got)
	}
}

func awaitWriteError(conn net.Conn, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	payload := bytes.Repeat([]byte("w"), 32*1024)
	for time.Now().Before(deadline) {
		_, err := conn.Write(payload)
		if err != nil {
			return err
		}
		time.Sleep(10 * time.Millisecond)
	}
	return errors.New("expected write to fail after relay context cancellation")
}

func startInProcessTCPConnectProxy(t *testing.T, handler func(targetHost, targetPort string, r *http.Request, w http.ResponseWriter)) int {
	t.Helper()
	quicConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("listen quic udp: %v", err)
	}
	proxyPort := quicConn.LocalAddr().(*net.UDPAddr).Port

	mux := http.NewServeMux()
	mux.HandleFunc("/masque/tcp/{target_host}/{target_port}", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		handler(r.PathValue("target_host"), r.PathValue("target_port"), r, w)
	})
	server := http3.Server{
		TLSConfig:       connectUDPTestTLS,
		QUICConfig:      &quic.Config{EnableDatagrams: true},
		EnableDatagrams: true,
		Handler:         mux,
	}
	var serveWG sync.WaitGroup
	serveWG.Add(1)
	go func() {
		defer serveWG.Done()
		_ = server.Serve(quicConn)
	}()
	t.Cleanup(func() {
		_ = server.Close()
		serveWG.Wait()
		_ = quicConn.Close()
	})
	time.Sleep(20 * time.Millisecond)
	return proxyPort
}

func TestSnapshotMetricsIncludesErrorClassCounters(t *testing.T) {
	before := SnapshotMetrics()
	recordTCPDialFailure()
	recordTCPDialErrorClass(ErrTCPDial)
	recordTCPDialErrorClass(ErrPolicyFallbackDenied)
	recordTCPDialErrorClass(ErrTCPOverConnectIP)
	recordTCPDialErrorClass(errors.New("unknown"))
	after := SnapshotMetrics()

	if after.TCPDialFailTotal < before.TCPDialFailTotal+1 {
		t.Fatalf("expected dial fail counter increment, before=%d after=%d", before.TCPDialFailTotal, after.TCPDialFailTotal)
	}
	if after.TCPErrorClassDialTotal < before.TCPErrorClassDialTotal+1 {
		t.Fatalf("expected dial class counter increment, before=%d after=%d", before.TCPErrorClassDialTotal, after.TCPErrorClassDialTotal)
	}
	if after.TCPErrorClassPolicyTotal < before.TCPErrorClassPolicyTotal+1 {
		t.Fatalf("expected policy class counter increment, before=%d after=%d", before.TCPErrorClassPolicyTotal, after.TCPErrorClassPolicyTotal)
	}
	if after.TCPErrorClassCapTotal < before.TCPErrorClassCapTotal+1 {
		t.Fatalf("expected capability class counter increment, before=%d after=%d", before.TCPErrorClassCapTotal, after.TCPErrorClassCapTotal)
	}
	if after.TCPErrorClassOtherTotal < before.TCPErrorClassOtherTotal+1 {
		t.Fatalf("expected other class counter increment, before=%d after=%d", before.TCPErrorClassOtherTotal, after.TCPErrorClassOtherTotal)
	}
}

func TestConnectIPObservabilitySnapshotPolicyReasonContract(t *testing.T) {
	snapshot := ConnectIPObservabilitySnapshot()
	reasonMapRaw, ok := snapshot["connect_ip_policy_drop_icmp_reason_total"]
	if !ok {
		t.Fatal("expected connect_ip_policy_drop_icmp_reason_total key in observability snapshot")
	}
	reasonMap, ok := reasonMapRaw.(map[string]uint64)
	if !ok {
		t.Fatalf("unexpected policy-drop reason map type: %T", reasonMapRaw)
	}
	for _, reason := range []string{"src_not_allowed", "dst_not_allowed", "proto_not_allowed"} {
		_, exists := reasonMap[reason]
		if !exists {
			t.Fatalf("expected mandatory policy-drop reason key %q", reason)
		}
	}
	if ClassifyError(ErrPolicyFallbackDenied) != ErrorClassPolicy {
		t.Fatal("expected ErrPolicyFallbackDenied to stay classified as policy")
	}
}

func TestConnectIPObservabilitySnapshotIncludesHTTP3StreamDatagramQueueDrops(t *testing.T) {
	snapshot := ConnectIPObservabilitySnapshot()
	raw, ok := snapshot["http3_stream_datagram_queue_drop_total"]
	if !ok {
		t.Fatal("expected http3_stream_datagram_queue_drop_total in ConnectIPObservabilitySnapshot")
	}
	if _, ok := raw.(uint64); !ok {
		t.Fatalf("unexpected type for http3_stream_datagram_queue_drop_total: %T", raw)
	}
}

func TestConnectIPObservabilitySnapshotIncludesQUICDatagramRcvQueueDrops(t *testing.T) {
	snapshot := ConnectIPObservabilitySnapshot()
	raw, ok := snapshot["quic_datagram_rcv_queue_drop_total"]
	if !ok {
		t.Fatal("expected quic_datagram_rcv_queue_drop_total in ConnectIPObservabilitySnapshot")
	}
	if _, ok := raw.(uint64); !ok {
		t.Fatalf("unexpected type for quic_datagram_rcv_queue_drop_total: %T", raw)
	}
}

type fakeIPPacketSession struct{}

func (f fakeIPPacketSession) ReadPacket(buffer []byte) (int, error) { return 0, nil }
func (f fakeIPPacketSession) WritePacket(buffer []byte) ([]byte, error) {
	return nil, nil
}
func (f fakeIPPacketSession) Close() error { return nil }

type recordingIPPacketSession struct {
	lastWrite  []byte
	writes     [][]byte
	readPacket []byte
}

func (s *recordingIPPacketSession) ReadPacket(buffer []byte) (int, error) {
	if len(s.readPacket) == 0 {
		return 0, io.EOF
	}
	n := copy(buffer, s.readPacket)
	s.readPacket = nil
	return n, nil
}

func (s *recordingIPPacketSession) WritePacket(buffer []byte) ([]byte, error) {
	packet := append([]byte(nil), buffer...)
	s.lastWrite = packet
	s.writes = append(s.writes, packet)
	return nil, nil
}

func (s *recordingIPPacketSession) Close() error { return nil }

func TestParseICMPPTBHopMTUIPv4(t *testing.T) {
	pkt := make([]byte, 28)
	pkt[0] = 0x45
	pkt[9] = 1
	icmpOff := 20
	pkt[icmpOff] = 3
	pkt[icmpOff+1] = 4
	binary.BigEndian.PutUint16(pkt[icmpOff+6:icmpOff+8], 1200)
	mtu, v6, ok := parseICMPPTBHopMTU(pkt)
	if !ok || v6 || mtu != 1200 {
		t.Fatalf("parse: mtu=%d v6=%v ok=%v", mtu, v6, ok)
	}
}

func TestParseICMPPTBHopMTUIPv6(t *testing.T) {
	pkt := make([]byte, 48)
	pkt[0] = 0x60
	pkt[6] = 58
	icmpOff := 40
	pkt[icmpOff] = 2
	pkt[icmpOff+1] = 0
	binary.BigEndian.PutUint32(pkt[icmpOff+4:icmpOff+8], 1400)
	mtu, v6, ok := parseICMPPTBHopMTU(pkt)
	if !ok || !v6 || mtu != 1400 {
		t.Fatalf("parse: mtu=%d v6=%v ok=%v", mtu, v6, ok)
	}
}

type fakeDeadlineReader struct{}

func (f *fakeDeadlineReader) Read(_ []byte) (int, error) { return 0, io.EOF }

type fakeWriter struct{}

func (f *fakeWriter) Write(p []byte) (int, error) { return len(p), nil }
func (f *fakeWriter) Close() error                { return nil }

type trackedReadCloser struct {
	closed int
}

func (r *trackedReadCloser) Read(_ []byte) (int, error) { return 0, io.EOF }
func (r *trackedReadCloser) Close() error {
	r.closed++
	return nil
}

type trackedWriteCloser struct {
	closed int
}

func (w *trackedWriteCloser) Write(p []byte) (int, error) { return len(p), nil }
func (w *trackedWriteCloser) Close() error {
	w.closed++
	return nil
}

type roundTripperFunc func(req *http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

type contextBoundReadCloser struct {
	ctx context.Context
}

func (r *contextBoundReadCloser) Read(_ []byte) (int, error) {
	<-r.ctx.Done()
	return 0, context.Cause(r.ctx)
}

func (r *contextBoundReadCloser) Close() error {
	return nil
}
