package masque

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	connectip "github.com/quic-go/connect-ip-go"
	qmasque "github.com/quic-go/masque-go"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/sagernet/sing-box/option"
	mcip "github.com/sagernet/sing-box/transport/masque/connectip"
	"github.com/sagernet/sing-box/transport/masque/httpx"
	msess "github.com/sagernet/sing-box/transport/masque/session"
	strm "github.com/sagernet/sing-box/transport/masque/stream"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/yosida95/uritemplate/v3"
	"golang.org/x/net/http2"
)

type timeoutNetError struct{ msg string }

// nopTCPNetstack implements TCPNetstack for hop-reset teardown tests only.
type nopTCPNetstack struct {
	closeCalled atomic.Bool
}

func (n *nopTCPNetstack) DialContext(ctx context.Context, destination M.Socksaddr) (net.Conn, error) {
	return nil, errors.New("nop")
}

func (n *nopTCPNetstack) Close() error {
	n.closeCalled.Store(true)
	return nil
}

type connectIPTeardownOrderNetstack struct {
	ipConnStillSet func() bool
}

func (n *connectIPTeardownOrderNetstack) DialContext(ctx context.Context, destination M.Socksaddr) (net.Conn, error) {
	return nil, errors.New("nop")
}

func (n *connectIPTeardownOrderNetstack) Close() error {
	if n.ipConnStillSet != nil && n.ipConnStillSet() {
		return errors.New("tcp netstack closed before shared connect-ip conn")
	}
	return nil
}

func TestHTTPFallbackSwitchConnectIPTeardownOrder(t *testing.T) {
	s := newTestCoreSession(msess.CoreSession{
		HTTPLayerAuto: true,
		IPConn:            testStubConnectIPConn(),
	})
	s.UDPHTTPLayer.Store(option.MasqueHTTPLayerH3)
	orderNS := &connectIPTeardownOrderNetstack{
		ipConnStillSet: func() bool { return s.IPConn != nil },
	}
	s.TCPNetstack = orderNS

	s.Mu.Lock()
	switched := s.tryHTTPFallbackSwitchLockedAssumeMu(errors.New("Extended CONNECT refused"))
	s.Mu.Unlock()
	if !switched {
		t.Fatal("expected http layer fallback switch")
	}
	if s.IPConn != nil {
		t.Fatal("expected ipConn cleared after fallback teardown")
	}
	if s.TCPNetstack != nil {
		t.Fatal("expected tcpNetstack cleared after fallback teardown")
	}
	if layer, _ := s.UDPHTTPLayer.Load().(string); layer != option.MasqueHTTPLayerH2 {
		t.Fatalf("expected overlay pivot to h2, got %q", layer)
	}
}

func TestReleaseOpenedConnectIPSessionTeardownOrder(t *testing.T) {
	s := newTestCoreSession(msess.CoreSession{
		IPConn: testStubConnectIPConn(),
	})
	orderNS := &connectIPTeardownOrderNetstack{
		ipConnStillSet: func() bool { return s.IPConn != nil },
	}
	s.TCPNetstack = orderNS

	s.releaseOpenedConnectIPSessionIfAbandoned()

	if s.IPConn != nil {
		t.Fatal("expected ipConn cleared after abandon teardown")
	}
	if s.TCPNetstack != nil {
		t.Fatal("expected tcpNetstack cleared after abandon teardown")
	}
}

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

func TestTcpMasqueConnectStreamChosenLogFields(t *testing.T) {
	t.Parallel()
	u, err := url.Parse("https://proxy.example/tcp/{target_host}/{target_port}")
	if err != nil {
		t.Fatal(err)
	}
	opts := ClientOptions{Server: "edge.example", ServerPort: 443}
	wantDial := masqueDialTarget(masqueQuicDialCandidateHost(opts), 443)
	host, dial := tcpMasqueConnectStreamChosenLogFields(u, opts)
	if host != "proxy.example" {
		t.Fatalf("target authority: got %q", host)
	}
	if dial != wantDial {
		t.Fatalf("dial: got %q want %q", dial, wantDial)
	}
	uEmptyHost, err := url.Parse("/masque/tcp/{target_host}/{target_port}")
	if err != nil {
		t.Fatal(err)
	}
	host2, dial2 := tcpMasqueConnectStreamChosenLogFields(uEmptyHost, opts)
	if host2 != "edge.example:443" {
		t.Fatalf("empty URL.Host falls back to Server:Port: got %q", host2)
	}
	if dial2 != wantDial {
		t.Fatalf("dial parity: got %q", dial2)
	}
	optsZero := ClientOptions{Server: "srv.example", ServerPort: 0}
	_, dial0 := tcpMasqueConnectStreamChosenLogFields(u, optsZero)
	if want0 := masqueDialTarget(masqueQuicDialCandidateHost(optsZero), 443); dial0 != want0 {
		t.Fatalf("implicit 443 dial: got %q want %q", dial0, want0)
	}
}

func TestResolveTLSServerNameTrimmed(t *testing.T) {
	t.Parallel()
	if got := resolveTLSServerName(ClientOptions{MasqueQUICCryptoTLS: &tls.Config{ServerName: "  sni.example  "}, Server: "  ignored.example "}); got != "sni.example" {
		t.Fatalf("explicit SNI: got %q", got)
	}
	if got := resolveTLSServerName(ClientOptions{Server: "  host.example "}); got != "host.example" {
		t.Fatalf("fallback Server: got %q", got)
	}
	if got := resolveTLSServerName(ClientOptions{MasqueQUICCryptoTLS: &tls.Config{ServerName: "\t "}, Server: "edge.example"}); got != "edge.example" {
		t.Fatalf("whitespace-only SNI falls back to Server: got %q", got)
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

func TestCoreSessionGetTCPRoundTripperUnderSessionMutex(t *testing.T) {
	t.Parallel()
	// CONNECT-IP (openIPSessionLocked) and ListenPacket/connect_ip dial while holding s.Mu.
	// getTCPRoundTripper must not acquire s.Mu or the session deadlocks before the network round-trip.
	naked := newTestCoreSession(msess.CoreSession{})
	naked.Mu.Lock()
	rt := naked.getTCPRoundTripper(http.DefaultTransport)
	naked.Mu.Unlock()
	if rt != http.DefaultTransport {
		t.Fatalf("expected DefaultTransport without override, got %T", rt)
	}
	injected := newTestCoreSession(msess.CoreSession{
			TCPRoundTripper: roundTripperFunc(func(*http.Request) (*http.Response, error) {
			return nil, errors.New("stub")
		}),
		})
	injected.Mu.Lock()
	rt = injected.getTCPRoundTripper(http.DefaultTransport)
	injected.Mu.Unlock()
	if rt == http.DefaultTransport {
		t.Fatal("expected injected RoundTripper when tcpRoundTripper is set")
	}
}

func TestDialTCPStreamAdvancesHopChainAfterRetries(t *testing.T) {
	var mu sync.Mutex
	var dialHosts []string
	session := newTestCoreSession(msess.CoreSession{
			Options: ClientOptions{
			Server:                   "hop1.example",
			ServerPort:               443,
			MasqueEffectiveHTTPLayer: option.MasqueHTTPLayerH3,
		},
			HopOrder: []HopOptions{
			{Tag: "hop1", Server: "hop1.example", Port: 443},
			{Tag: "hop2", Via: "hop1", Server: "hop2.example", Port: 8443},
		},
			HopIndex: 0,
			Caps: CapabilitySet{ConnectTCP: true},
			TCPRoundTripper: roundTripperFunc(func(req *http.Request) (*http.Response, error) {
			mu.Lock()
			dialHosts = append(dialHosts, req.Host)
			mu.Unlock()
			// Must be retryable for dialTCPStreamHTTP3 inner loop (same as UDP hop logic after datagram failures).
			return nil, timeoutNetError{msg: "timeout while connecting"}
		}),
		})
	session.UDPHTTPLayer.Store(option.MasqueHTTPLayerH3)
	_, _, tcp, err := buildTemplates(ClientOptions{
		Server:     "hop1.example",
		ServerPort: 443,
		Hops: []HopOptions{
			{Tag: "hop1", Server: "hop1.example", Port: 443},
			{Tag: "hop2", Via: "hop1", Server: "hop2.example", Port: 8443},
		},
	})
	if err != nil {
		t.Fatalf("buildTemplates: %v", err)
	}
	session.TemplateTCP = tcp
	_, err = session.dialTCPStream(context.Background(), M.ParseSocksaddrHostPort("example.com", 443))
	if err == nil {
		t.Fatal("expected error after exhausting hop chain")
	}
	mu.Lock()
	defer mu.Unlock()
	if len(dialHosts) != 6 {
		t.Fatalf("expected 3 http3 round-trip attempts per hop Г— 2 hops = 6, got %d (%v)", len(dialHosts), dialHosts)
	}
	for i := 0; i < 3; i++ {
		if dialHosts[i] != "hop1.example:443" {
			t.Fatalf("hop1 round-trip %d: expected host hop1.example:443, got %q", i, dialHosts[i])
		}
	}
	for i := 3; i < 6; i++ {
		if dialHosts[i] != "hop2.example:8443" {
			t.Fatalf("hop2 round-trip %d: expected host hop2.example:8443, got %q", i, dialHosts[i])
		}
	}
	if session.Options.Server != "hop2.example" || session.Options.ServerPort != 8443 {
		t.Fatalf("expected session settled on last hop server, got %s:%d", session.Options.Server, session.Options.ServerPort)
	}
}

func TestDialTCPStreamDoesNotAdvanceHopOnLocalConfigError(t *testing.T) {
	session := newTestCoreSession(msess.CoreSession{
			Options: ClientOptions{
			Server:                   "hop1.example",
			ServerPort:               443,
			MasqueEffectiveHTTPLayer: option.MasqueHTTPLayerH3,
		},
			HopOrder: []HopOptions{
			{Tag: "hop1", Server: "hop1.example", Port: 443},
			{Tag: "hop2", Via: "hop1", Server: "hop2.example", Port: 8443},
		},
			HopIndex: 0,
			Caps: CapabilitySet{ConnectTCP: true},
			HTTPLayerAuto: true,
		})
	session.UDPHTTPLayer.Store(option.MasqueHTTPLayerH3)
	_, _, tcp, err := buildTemplates(ClientOptions{
		Server:     "hop1.example",
		ServerPort: 443,
		Hops: []HopOptions{
			{Tag: "hop1", Server: "hop1.example", Port: 443},
			{Tag: "hop2", Via: "hop1", Server: "hop2.example", Port: 8443},
		},
	})
	if err != nil {
		t.Fatalf("buildTemplates: %v", err)
	}
	session.TemplateTCP = tcp
	_, err = session.dialTCPStream(context.Background(), M.Socksaddr{})
	if err == nil {
		t.Fatal("expected error for invalid destination")
	}
	if !errors.Is(err, msess.ErrCapability) {
		t.Fatalf("expected msess.ErrCapability, got %v", err)
	}
	if session.HopIndex != 0 {
		t.Fatalf("expected hop chain untouched (invalid destination), hopIndex=%d", session.HopIndex)
	}
	if session.Options.Server != "hop1.example" || session.Options.ServerPort != 443 {
		t.Fatalf("expected entry hop unchanged, got %s:%d", session.Options.Server, session.Options.ServerPort)
	}
}

func TestCoreSessionAdvanceHop(t *testing.T) {
	session := newTestCoreSession(msess.CoreSession{
			HopOrder: []HopOptions{
			{Tag: "h1", Server: "h1.example", Port: 443},
			{Tag: "h2", Via: "h1", Server: "h2.example", Port: 8443},
		},
		})
	if !session.advanceHop() {
		t.Fatal("expected first advanceHop to succeed")
	}
	if session.HopIndex != 1 {
		t.Fatalf("unexpected hop index: %d", session.HopIndex)
	}
	if session.advanceHop() {
		t.Fatal("expected second advanceHop to fail at chain end")
	}
}

func TestResetHopTemplatesClearsTCPNetstack(t *testing.T) {
	ns := &nopTCPNetstack{}
	session := newTestCoreSession(msess.CoreSession{
			Options: ClientOptions{
			Server: "entry.example",
			Hops: []HopOptions{
				{Tag: "entry", Server: "entry.example", Port: 443},
				{Tag: "next", Via: "entry", Server: "next.example", Port: 8443},
			},
		},
			HopOrder: []HopOptions{
			{Tag: "entry", Server: "entry.example", Port: 443},
			{Tag: "next", Via: "entry", Server: "next.example", Port: 8443},
		},
			HopIndex: 1,
			TCPNetstack: ns,
		})
	if err := session.resetHopTemplates(); err != nil {
		t.Fatalf("resetHopTemplates failed: %v", err)
	}
	if session.TCPNetstack != nil {
		t.Fatal("expected tcpNetstack cleared on hop reset")
	}
	if !ns.closeCalled.Load() {
		t.Fatal("expected TCP netstack Close on hop reset")
	}
}

func TestResetHopTemplatesClearsTCPHTTPTransport(t *testing.T) {
	session := newTestCoreSession(msess.CoreSession{
			Options: ClientOptions{
			Server: "entry.example",
			Hops: []HopOptions{
				{Tag: "entry", Server: "entry.example", Port: 443},
				{Tag: "next", Via: "entry", Server: "next.example", Port: 8443},
			},
		},
			HopOrder: []HopOptions{
			{Tag: "entry", Server: "entry.example", Port: 443},
			{Tag: "next", Via: "entry", Server: "next.example", Port: 8443},
		},
			HopIndex: 1,
			TCPHTTP: &http3.Transport{},
		})

	if err := session.resetHopTemplates(); err != nil {
		t.Fatalf("resetHopTemplates failed: %v", err)
	}
	if session.TCPHTTP != nil {
		t.Fatal("expected tcpHTTP transport cache to be cleared on hop reset")
	}
}

func TestResetHopTemplatesClearsSharedIPH3Refs(t *testing.T) {
	shared := &http3.Transport{}
	session := newTestCoreSession(msess.CoreSession{
			Options: ClientOptions{
			Server: "entry.example",
			Hops: []HopOptions{
				{Tag: "entry", Server: "entry.example", Port: 443},
				{Tag: "next", Via: "entry", Server: "next.example", Port: 8443},
			},
		},
			HopOrder: []HopOptions{
			{Tag: "entry", Server: "entry.example", Port: 443},
			{Tag: "next", Via: "entry", Server: "next.example", Port: 8443},
		},
			HopIndex: 1,
			TCPHTTP: shared,
			IPHTTP: shared,
		})
	if err := session.resetHopTemplates(); err != nil {
		t.Fatalf("resetHopTemplates failed: %v", err)
	}
	if session.IPHTTP != nil || session.TCPHTTP != nil || session.IPHTTPConn != nil {
		t.Fatalf("expected shared ip/tcp http3.Transport cleared on hop reset, ipHTTP=%v tcpHTTP=%v ipHTTPConn=%v", session.IPHTTP, session.TCPHTTP, session.IPHTTPConn)
	}
}

func TestResetTCPHTTPTransportClearsSharedIPH3Refs(t *testing.T) {
	shared := &http3.Transport{}
	s := newTestCoreSession(msess.CoreSession{
			Options: ClientOptions{
			Server:     "example.com",
			ServerPort: 443,
		},
			TCPHTTP: shared,
			IPHTTP: shared,
		})
	s.resetTCPHTTPTransport()
	if s.TCPHTTP == nil || s.TCPHTTP == shared {
		t.Fatal("expected fresh tcpHTTP after reset")
	}
	if s.IPHTTP != nil || s.IPHTTPConn != nil {
		t.Fatal("expected shared CONNECT-IP http3.Transport pointer cleared alongside tcpHTTP rebuild")
	}
}

func TestResetHopTemplatesClearsDialPeerOnInnerHop(t *testing.T) {
	session := newTestCoreSession(msess.CoreSession{
			Options: ClientOptions{
			Server:     "entry.example",
			DialPeer:   "203.0.113.77",
			ServerPort: 443,
			Hops: []HopOptions{
				{Tag: "entry", Server: "entry.example", Port: 443},
				{Tag: "next", Via: "entry", Server: "next.example", Port: 8443},
			},
		},
			HopOrder: []HopOptions{
			{Tag: "entry", Server: "entry.example", Port: 443},
			{Tag: "next", Via: "entry", Server: "next.example", Port: 8443},
		},
			HopIndex: 1,
		})
	if err := session.resetHopTemplates(); err != nil {
		t.Fatalf("resetHopTemplates failed: %v", err)
	}
	if session.Options.Server != "next.example" || session.Options.ServerPort != 8443 {
		t.Fatalf("unexpected hop templates server: got %s:%d", session.Options.Server, session.Options.ServerPort)
	}
	if strings.TrimSpace(session.Options.DialPeer) != "" {
		t.Fatalf("expected DialPeer cleared past entry hop, got %q", session.Options.DialPeer)
	}
}

func TestResetHopTemplatesPreservesHTTPOverlay(t *testing.T) {
	session := newTestCoreSession(msess.CoreSession{
			Options: ClientOptions{
			Server:                   "entry.example",
			MasqueEffectiveHTTPLayer: option.MasqueHTTPLayerH3,
			Hops: []HopOptions{
				{Tag: "entry", Server: "entry.example", Port: 443},
				{Tag: "next", Via: "entry", Server: "next.example", Port: 8443},
			},
		},
			HopOrder: []HopOptions{
			{Tag: "entry", Server: "entry.example", Port: 443},
			{Tag: "next", Via: "entry", Server: "next.example", Port: 8443},
		},
			HopIndex: 1,
		})
	session.UDPHTTPLayer.Store(option.MasqueHTTPLayerH2)
	session.HTTPFallbackConsumed.Store(true)

	if err := session.resetHopTemplates(); err != nil {
		t.Fatalf("resetHopTemplates failed: %v", err)
	}
	if session.currentUDPHTTPLayer() != option.MasqueHTTPLayerH2 {
		t.Fatalf("expected udp overlay h2 preserved across hop reset, got %q", session.currentUDPHTTPLayer())
	}
	if session.HTTPFallbackConsumed.Load() {
		t.Fatal("expected httpFallbackConsumed reset to false for the new hop")
	}
}

func TestMaybeRecordHTTPLayerCacheSuccessSkipsInnerHop(t *testing.T) {
	var calls atomic.Int32
	s := newTestCoreSession(msess.CoreSession{
			Options: ClientOptions{
			Server:                   "hop2.example",
			ServerPort:               8443,
			MasqueEffectiveHTTPLayer: option.MasqueHTTPLayerAuto,
			HTTPLayerSuccess: func(layer string, id HTTPLayerCacheDialIdentity) {
				calls.Add(1)
			},
		},
			HopOrder: []HopOptions{
			{Tag: "hop1", Server: "hop1.example", Port: 443},
			{Tag: "hop2", Via: "hop1", Server: "hop2.example", Port: 8443},
		},
			HopIndex: 1,
		})
	s.maybeRecordHTTPLayerCacheSuccess(option.MasqueHTTPLayerH2)
	if calls.Load() != 0 {
		t.Fatalf("expected no cache record on inner hop, got %d calls", calls.Load())
	}
	s.HopIndex = 0
	s.maybeRecordHTTPLayerCacheSuccess(option.MasqueHTTPLayerH3)
	if calls.Load() != 1 {
		t.Fatalf("expected one cache record on entry hop, got %d", calls.Load())
	}
}

func TestDialConnectIPAttemptHookRecordsHTTPLayerCacheSuccess(t *testing.T) {
	okConn := testStubConnectIPConn()
	var gotLayer atomic.Value
	s := func() *coreSession {
		s := newTestCoreSession(msess.CoreSession{
			Options: ClientOptions{
			DataplaneMode: option.MasqueDataplaneConnectIP,
			Server:        "example.com",
			ServerPort:    443,
			HTTPLayerSuccess: func(layer string, id HTTPLayerCacheDialIdentity) {
				gotLayer.Store(layer)
			},
		},
		})
		cs := &coreSession{CoreSession: s.CoreSession, 	dialConnectIPAttemptHook: func(ctx context.Context, useHTTP2 bool) (*connectip.Conn, error) {
			return okConn, nil
		}}
		return cs
	}()
	s.HopOrder = nil
	s.HopIndex = 0

	if _, err := s.dialConnectIPAttempt(context.Background(), false); err != nil {
		t.Fatalf("dialConnectIPAttempt h3 hook: %v", err)
	}
	if l, _ := gotLayer.Load().(string); l != option.MasqueHTTPLayerH3 {
		t.Fatalf("cache layer want %q got %q", option.MasqueHTTPLayerH3, l)
	}

	gotLayer.Store("")
	if _, err := s.dialConnectIPAttempt(context.Background(), true); err != nil {
		t.Fatalf("dialConnectIPAttempt h2 hook: %v", err)
	}
	if l, _ := gotLayer.Load().(string); l != option.MasqueHTTPLayerH2 {
		t.Fatalf("cache layer want %q got %q", option.MasqueHTTPLayerH2, l)
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

func TestBuildTemplatesWarpMasqueUsqueConnectIPURL(t *testing.T) {
	_, ip, _, err := buildTemplates(ClientOptions{
		Server:                "engage.cloudflareclient.com",
		ServerPort:            443,
		WarpConnectIPProtocol: "cf-connect-ip",
	})
	if err != nil {
		t.Fatalf("buildTemplates: %v", err)
	}
	if ip == nil {
		t.Fatal("expected ip template")
	}
	if got := ip.Raw(); got != "https://cloudflareaccess.com" {
		t.Fatalf("CONNECT-IP template must match usque internal.ConnectURI, got %q", got)
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
	if !errors.Is(err, msess.ErrCapability) {
		t.Fatalf("expected msess.ErrCapability for unsupported flow forwarding variable, got: %v", err)
	}
	if got := msess.ClassifyError(err); got != msess.ErrorClassCapability {
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
	if actualClass != msess.ErrorClassCapability {
		t.Fatalf("expected transport malformed scope classification capability, got: %s (err=%v)", actualClass, err)
	}
	if resultClass != msess.ErrorClassCapability {
		t.Fatalf("expected wrapped malformed scope classification capability, got: %s (err=%v)", resultClass, err)
	}
}

func TestCoreClientFactoryCapabilitiesByDataplaneMode(t *testing.T) {
	defaultSession, err := (CoreClientFactory{}).NewSession(context.TODO(), ClientOptions{
		Server:     "example.com",
		ServerPort: 443,
	})
	if err != nil {
		t.Fatalf("new default session: %v", err)
	}
	if !defaultSession.Capabilities().ConnectTCP {
		t.Fatal("expected default session to advertise ConnectTCP")
	}
	if !defaultSession.Capabilities().ConnectUDP {
		t.Fatal("expected default session to advertise ConnectUDP")
	}

	connectIPSession, err := (CoreClientFactory{}).NewSession(context.TODO(), ClientOptions{
		Server:        "example.com",
		ServerPort:    443,
		DataplaneMode: option.MasqueDataplaneConnectIP,
	})
	if err != nil {
		t.Fatalf("new connect_ip session: %v", err)
	}
	if !connectIPSession.Capabilities().ConnectTCP {
		t.Fatal("expected connect_ip session to advertise ConnectTCP")
	}
}

func TestDirectClientFactoryCapabilitiesByDataplaneMode(t *testing.T) {
	defaultSession, err := (DirectClientFactory{}).NewSession(context.TODO(), ClientOptions{})
	if err != nil {
		t.Fatalf("new direct default session: %v", err)
	}
	if !defaultSession.Capabilities().ConnectTCP {
		t.Fatal("expected direct default session to advertise ConnectTCP")
	}
	if !defaultSession.Capabilities().ConnectUDP {
		t.Fatal("expected direct default session to advertise ConnectUDP")
	}

	ipSession, err := (DirectClientFactory{}).NewSession(context.TODO(), ClientOptions{
		DataplaneMode: option.MasqueDataplaneConnectIP,
	})
	if err != nil {
		t.Fatalf("new direct connect_ip session: %v", err)
	}
	if ipSession.Capabilities().ConnectTCP {
		t.Fatal("expected direct connect_ip session to disable ConnectTCP in TUN-only mode")
	}
	if ipSession.Capabilities().ConnectUDP {
		t.Fatal("expected direct connect_ip session to disable ConnectUDP")
	}
	if !ipSession.Capabilities().ConnectIP {
		t.Fatal("expected direct connect_ip session to advertise ConnectIP")
	}
}

func TestCoreSessionDialContextRejectsNonTCPNetwork(t *testing.T) {
	session := newTestCoreSession(msess.CoreSession{
			Options: ClientOptions{
		},
		})
	_, err := session.DialContext(context.Background(), "udp", M.ParseSocksaddrHostPort("example.com", 443))
	if err == nil {
		t.Fatal("expected non-tcp network to fail fast in core session")
	}
	if !errors.Is(err, msess.ErrUnsupportedNetwork) {
		t.Fatalf("expected msess.ErrUnsupportedNetwork for non-tcp core boundary reject, got: %v", err)
	}
	if !strings.Contains(err.Error(), "unsupported network in masque session") {
		t.Fatalf("unexpected non-tcp boundary error: %v", err)
	}
	if got := msess.ClassifyError(err); got != msess.ErrorClassCapability {
		t.Fatalf("expected capability class for non-tcp core boundary reject, got: %s", got)
	}
}

func TestCoreSessionDialContextConnectIPReturnsTUNOnlyBoundary(t *testing.T) {
	session := newTestCoreSession(msess.CoreSession{
		Options: ClientOptions{
			DataplaneMode: option.MasqueDataplaneConnectIP,
		},
	})
	_, err := session.DialContext(context.Background(), "tcp", M.ParseSocksaddrHostPort("example.com", 443))
	if err == nil {
		t.Fatal("expected mode connect_ip to fail as TUN-only TCP path without netstack")
	}
	if got := msess.ClassifyError(err); got != msess.ErrorClassCapability {
		t.Fatalf("expected capability class for connect_ip tcp reject, got: %s (%v)", got, err)
	}
}

func TestStreamResolveDestinationHostRejectsInvalidDestination(t *testing.T) {
	_, err := strm.ResolveDestinationHost(M.Socksaddr{})
	if err == nil {
		t.Fatal("expected invalid destination to be rejected")
	}
	if !errors.Is(err, msess.ErrCapability) {
		t.Fatalf("expected msess.ErrCapability for invalid destination, got: %v", err)
	}
	if got := msess.ClassifyError(err); got != msess.ErrorClassCapability {
		t.Fatalf("expected capability class for invalid destination boundary reject, got: %s", got)
	}
}

func TestStreamResolveDestinationHostTrimsPaddedFqdn(t *testing.T) {
	dest := M.ParseSocksaddrHostPort("  example.com\t", 443)
	host, err := strm.ResolveDestinationHost(dest)
	if err != nil {
		t.Fatalf("ResolveDestinationHost: %v", err)
	}
	if host != "example.com" {
		t.Fatalf("expected trimmed fqdn example.com, got %q", host)
	}
}

func TestStreamResolveDestinationHostPaddedFqdnDoesNotOverrideIP(t *testing.T) {
	dest := M.Socksaddr{
		Addr: netip.MustParseAddr("198.51.100.1"),
		Port: 443,
		Fqdn: "  example.com ",
	}
	host, err := strm.ResolveDestinationHost(dest)
	if err != nil {
		t.Fatalf("ResolveDestinationHost: %v", err)
	}
	if host != "198.51.100.1" {
		t.Fatalf("expected IP when both addr and padded fqdn present, got %q", host)
	}
}

func TestStreamIsRetryableTCPStreamError(t *testing.T) {
	if !strm.IsRetryableTCPStreamError(&quic.IdleTimeoutError{}) {
		t.Fatal("expected timeout/no recent network activity to be retryable")
	}
	if !strm.IsRetryableTCPStreamError(&quic.ApplicationError{ErrorCode: 0x100, Remote: true}) {
		t.Fatal("expected application errors to be retryable")
	}
	if strm.IsRetryableTCPStreamError(net.ErrClosed) {
		t.Fatal("expected closed network connection to be non-retryable for tcp stream path")
	}
	if !strm.IsRetryableTCPStreamError(&net.OpError{Op: "read", Err: syscall.ECONNRESET}) {
		t.Fatal("expected TCP ECONNRESET to be retryable for H2 CONNECT-stream")
	}
	if !strm.IsRetryableTCPStreamError(http2.ConnectionError(http2.ErrCodeProtocol)) {
		t.Fatal("expected http2 connection error to be retryable")
	}
	joined := errors.Join(strm.Errs.TCPConnectStreamFailed, &quic.IdleTimeoutError{})
	if !strm.IsRetryableTCPStreamError(joined) {
		t.Fatal("expected errors.Join with idle timeout to be retryable")
	}
	if !strm.IsRetryableTCPStreamError(errors.New("http3: transport is closed")) {
		t.Fatal("expected http3 transport closed to be retryable")
	}
}

func TestStreamTCPConnectStreamErrMayBenefitFromNextHop(t *testing.T) {
	if strm.TCPConnectStreamErrMayBenefitFromNextHop(nil) {
		t.Fatal("nil error must not benefit from next hop")
	}
	capErr := errors.Join(msess.ErrCapability, errors.New("invalid destination"))
	if strm.TCPConnectStreamErrMayBenefitFromNextHop(capErr) {
		t.Fatal("capability errors must not consume hops")
	}
	if !strm.TCPConnectStreamErrMayBenefitFromNextHop(errors.New("connection reset")) {
		t.Fatal("transient overlay errors may benefit from next hop")
	}
}

func TestCoreSessionDialDirectTCPRejectsInvalidDestination(t *testing.T) {
	session := newTestCoreSession(msess.CoreSession{})
	_, err := session.dialDirectTCP(context.Background(), "tcp", M.Socksaddr{})
	if err == nil {
		t.Fatal("expected direct tcp dial to reject invalid destination")
	}
	if !errors.Is(err, msess.ErrCapability) {
		t.Fatalf("expected msess.ErrCapability for direct dial invalid destination, got: %v", err)
	}
	if got := msess.ClassifyError(err); got != msess.ErrorClassCapability {
		t.Fatalf("expected capability class for direct dial invalid destination, got: %s", got)
	}
}

func TestCoreSessionCloseClearsConnectIPHTTPStateAndIsIdempotent(t *testing.T) {
	session := newTestCoreSession(msess.CoreSession{
		IPHTTP:     &http3.Transport{},
		IPHTTPConn: &http3.ClientConn{},
	})
	if err := session.Close(); err != nil {
		t.Fatalf("first close returned error: %v", err)
	}
	if session.IPHTTP != nil {
		t.Fatal("expected close to clear cached connect-ip http3 transport")
	}
	if session.IPHTTPConn != nil {
		t.Fatal("expected close to clear cached connect-ip http3 client conn")
	}
	if err := session.Close(); err != nil {
		t.Fatalf("second close should stay idempotent, got error: %v", err)
	}
}

func TestCoreClientFactoryConnectIPDatagramCeilingClamp(t *testing.T) {
	testCases := []struct {
		name            string
		requested       uint32
		expectedCeiling int
	}{
		{name: "zero requested uses default ceiling max", requested: 0, expectedCeiling: mcip.DefaultDatagramCeilingMax},
		{name: "below lower bound clamps to 1280", requested: 1200, expectedCeiling: 1280},
		{name: "within bounds preserved", requested: 1400, expectedCeiling: 1400},
		{name: "jumbo mtu from JSON preserved", requested: 5000, expectedCeiling: 5000},
		{name: "above configured max clamps", requested: 10000, expectedCeiling: mcip.MaxConfiguredDatagramCeiling},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
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
			if core.ConnectIPDatagramCeiling != tc.expectedCeiling {
				t.Fatalf("unexpected connect ip datagram ceiling: got=%d want=%d", core.ConnectIPDatagramCeiling, tc.expectedCeiling)
			}
		})
	}
}

func TestBuildAndParseIPv4UDPPacket(t *testing.T) {
	src := netip.MustParseAddr("198.18.0.2")
	dst := netip.MustParseAddr("10.200.0.2")
	payload := []byte("hello-masque")
	packet, err := mcip.BuildIPv4UDPPacket(src, 53000, dst, 5601, payload)
	if err != nil {
		t.Fatalf("build packet: %v", err)
	}
	gotPayload, gotSrc, gotSrcPort, err := mcip.ParseIPv4UDPPacket(packet)
	if err != nil {
		t.Fatalf("parse packet: %v", err)
	}
	if gotSrc != src || gotSrcPort != 53000 || !bytes.Equal(gotPayload, payload) {
		t.Fatalf("unexpected roundtrip: src=%s port=%d payload=%q", gotSrc, gotSrcPort, gotPayload)
	}
}


func TestHTTPFallbackBudgetResetsAfterSuccessfulUDPDial(t *testing.T) {
	templateUDP, err := uritemplate.New("https://example.com/masque/udp/{target_host}/{target_port}")
	if err != nil {
		t.Fatalf("build udp template: %v", err)
	}
	pc, listenErr := net.ListenPacket("udp", "127.0.0.1:0")
	if listenErr != nil {
		t.Fatalf("listen udp: %v", listenErr)
	}
	defer pc.Close()

	session := func() *coreSession {
		s := newTestCoreSession(msess.CoreSession{
			Options: ClientOptions{
			MasqueEffectiveHTTPLayer: option.MasqueHTTPLayerH3,
			TCPDial: func(ctx context.Context, network, address string) (net.Conn, error) {
				t.Fatalf("unexpected TCP dial on mocked CONNECT-UDP path")
				return nil, nil
			},
		},
			TemplateUDP: templateUDP,
			Caps: CapabilitySet{ConnectUDP: true},
			HTTPLayerAuto: true,
			UDPClient: &qmasque.Client{},
		})
		cs := &coreSession{CoreSession: s.CoreSession, 	udpDial: func(ctx context.Context, client *qmasque.Client, template *uritemplate.Template, target string) (net.PacketConn, error) {
			return pc, nil
		}}
		return cs
	}()
	session.UDPHTTPLayer.Store(option.MasqueHTTPLayerH3)
	session.HTTPFallbackConsumed.Store(true)

	_, dialErr := session.dialUDPAddr(context.Background(), session.UDPClient, templateUDP, "127.0.0.1:5353")
	if dialErr != nil {
		t.Fatalf("dialUDPAddr: %v", dialErr)
	}
	if session.HTTPFallbackConsumed.Load() {
		t.Fatal("expected http_fallback budget cleared after a successful CONNECT-UDP handshake on this hop")
	}
}

func TestListenPacketHTTPFallbackRunsAfterReconnectDialSwitchableFailure(t *testing.T) {
	templateUDP, err := uritemplate.New("https://example.com/masque/udp/{target_host}/{target_port}")
	if err != nil {
		t.Fatalf("build udp template: %v", err)
	}
	var call atomic.Uint32
	session := func() *coreSession {
		s := newTestCoreSession(msess.CoreSession{
			Options: ClientOptions{
			MasqueEffectiveHTTPLayer: option.MasqueHTTPLayerH3,
			TCPDial: func(ctx context.Context, network, address string) (net.Conn, error) {
				return nil, errors.New("tcp dial stub")
			},
		},
			TemplateUDP: templateUDP,
			Caps: CapabilitySet{ConnectUDP: true, ConnectIP: false},
			HTTPLayerAuto: true,
			UDPClient: &qmasque.Client{},
		})
		cs := &coreSession{CoreSession: s.CoreSession, 	udpDial: func(ctx context.Context, client *qmasque.Client, template *uritemplate.Template, target string) (net.PacketConn, error) {
			n := call.Add(1)
			switch n {
			case 1:
				// Must not match httpx.IsLayerSwitchableFailure substrings (would consume fallback on first dial).
				return nil, errors.New("nonswitchable_stub_udp_dial_1")
			case 2:
				return nil, errors.New("Extended CONNECT not supported on this path")
			default:
				return nil, errors.New("unexpected extra udp dial")
			}
		}}
		return cs
	}()
	session.UDPHTTPLayer.Store(option.MasqueHTTPLayerH3)

	_, listenErr := session.ListenPacket(context.Background(), M.ParseSocksaddrHostPort("127.0.0.1", 5353))
	if listenErr == nil {
		t.Fatal("expected error when hop chain is exhausted and h2 dial fails")
	}
	if len(session.HopOrder) != 0 {
		t.Fatalf("test expects no masque hop chain, got %+v index=%d", session.HopOrder, session.HopIndex)
	}
	if session.currentUDPHTTPLayer() != option.MasqueHTTPLayerH2 {
		t.Fatalf("expected http_layer fallback after reconnect dial switchable failure, overlay=%q", session.currentUDPHTTPLayer())
	}
	if call.Load() != 2 {
		t.Fatalf("expected exactly two udpDial invocations on h3 before overlay switch, got %d", call.Load())
	}
	if session.HTTPFallbackConsumed.Load() {
		t.Fatal("expected httpFallbackConsumed cleared after exhausted ListenPacket so retries can pivot again")
	}
}

func TestListenPacketH2UDPTransportChurnBeforeHopPivot(t *testing.T) {
	templateUDP, err := uritemplate.New("https://example.com/masque/udp/{target_host}/{target_port}")
	if err != nil {
		t.Fatalf("build udp template: %v", err)
	}
	okPC := &tierBPacketConnStub{}
	var call atomic.Uint32
	var testSess *coreSession
	testSess = func() *coreSession {
		s := newTestCoreSession(msess.CoreSession{
			Options: ClientOptions{
				MasqueEffectiveHTTPLayer: option.MasqueHTTPLayerH2,
				TCPDial: func(ctx context.Context, network, address string) (net.Conn, error) {
					return nil, errors.New("tcp dial stub")
				},
			},
			TemplateUDP:       templateUDP,
			Caps:              CapabilitySet{ConnectUDP: true, ConnectIP: false},
		})
		cs := &coreSession{CoreSession: s.CoreSession, h2UDPConnectHook: func(ctx context.Context, template *uritemplate.Template, target string) (net.PacketConn, error) {
			if testSess.currentUDPHTTPLayer() != option.MasqueHTTPLayerH2 {
				t.Fatal("expected CONNECT-UDP dial on h2 overlay only")
			}
			n := call.Add(1)
			switch n {
			case 1:
				return nil, errors.New("nonswitchable_stub_h2_connect_udp_1")
			case 2:
				return okPC, nil
			default:
				return nil, errors.New("unexpected extra h2 CONNECT-UDP dial")
			}
		}}
		return cs
	}()
	testSess.UDPHTTPLayer.Store(option.MasqueHTTPLayerH2)

	pc, listenErr := testSess.ListenPacket(context.Background(), M.ParseSocksaddrHostPort("127.0.0.1", 5353))
	if listenErr != nil {
		t.Fatalf("ListenPacket: %v", listenErr)
	}
	if call.Load() != 2 {
		t.Fatalf("expected h2 transport churn then success (2 CONNECT-UDP attempts), got %d", call.Load())
	}
	defer pc.Close()
	if pc != okPC {
		t.Fatalf("expected h2 ListenPacket to return dial PacketConn without DatagramSplitConn, got %T", pc)
	}
}

func TestDialTCPStreamHTTPFallbackRunsAfterReconnectRoundTripSwitchableFailure(t *testing.T) {
	var h3RoundTrips atomic.Uint32
	session := newTestCoreSession(msess.CoreSession{
			Options: ClientOptions{
			Server:                   "example.com",
			ServerPort:               443,
			TemplateTCP:              "https://example.com/masque/tcp/{target_host}/{target_port}",
			MasqueEffectiveHTTPLayer: option.MasqueHTTPLayerH3,
			TCPDial: func(ctx context.Context, network, address string) (net.Conn, error) {
				return nil, errors.New("tcp dial stub")
			},
		},
			Caps: CapabilitySet{ConnectTCP: true},
			HTTPLayerAuto: true,
		})
	session.TCPRoundTripper = roundTripperFunc(func(req *http.Request) (*http.Response, error) {
		if session.currentUDPHTTPLayer() == option.MasqueHTTPLayerH3 {
			n := h3RoundTrips.Add(1)
			switch n {
			case 1:
				return nil, errors.New("nonswitchable_tcp_rt_outer_1")
			case 2:
				return nil, errors.New("Extended CONNECT not supported on this path")
			default:
				t.Fatalf("unexpected extra HTTP/3 CONNECT-stream RoundTrip #%d", n)
			}
		}
		return nil, errors.New("h2_connect_stream_round_trip_stub")
	})
	session.UDPHTTPLayer.Store(option.MasqueHTTPLayerH3)

	_, dialErr := session.dialTCPStream(context.Background(), M.ParseSocksaddrHostPort("example.com", 443))
	if dialErr == nil {
		t.Fatal("expected error once h2 path hits tcp dial stub")
	}
	if len(session.HopOrder) != 0 {
		t.Fatalf("test expects no masque hop chain, got %+v", session.HopOrder)
	}
	if session.currentUDPHTTPLayer() != option.MasqueHTTPLayerH2 {
		t.Fatalf("expected http_layer fallback after transport churn exposes switchable failure, overlay=%q", session.currentUDPHTTPLayer())
	}
	if got := h3RoundTrips.Load(); got != 2 {
		t.Fatalf("expected exactly two CONNECT-stream RoundTrips on overlay h3 before switch, got %d", got)
	}
	if session.HTTPFallbackConsumed.Load() {
		t.Fatal("expected httpFallbackConsumed cleared after exhausted dialTCPStream so retries can pivot again")
	}
}

func TestOpenIPSessionFailureClearsHTTPFallbackLatchForNextAttempt(t *testing.T) {
	templateIP, err := uritemplate.New("https://example.com/masque/ip")
	if err != nil {
		t.Fatalf("build ip template: %v", err)
	}
	session := func() *coreSession {
		s := newTestCoreSession(msess.CoreSession{
			Options: ClientOptions{
			DataplaneMode: option.MasqueDataplaneConnectIP,
			MasqueEffectiveHTTPLayer: option.MasqueHTTPLayerH3,
		},
			TemplateIP: templateIP,
			Caps: CapabilitySet{ConnectIP: true},
			HTTPLayerAuto: true,
		})
		cs := &coreSession{CoreSession: s.CoreSession, 	dialConnectIPAttemptHook: func(ctx context.Context, useHTTP2 bool) (*connectip.Conn, error) {
			if !useHTTP2 {
				return nil, errors.New("Extended CONNECT not supported")
			}
			return nil, errors.New("stub h2 connect-ip non-switchable failure")
		}}
		return cs
	}()
	session.UDPHTTPLayer.Store(option.MasqueHTTPLayerH3)

	_, openErr := session.OpenIPSession(context.Background())
	if openErr == nil {
		t.Fatal("expected error from stubbed connect-ip dials")
	}
	if session.HTTPFallbackConsumed.Load() {
		t.Fatal("expected httpFallbackConsumed cleared after a wholly failed open so the next try can pivot again")
	}
}

func TestOpenIPSessionHTTPFallbackRunsAfterIPH3ReconnectDialSwitchableFailure(t *testing.T) {
	templateIP, err := uritemplate.New("https://example.com/masque/ip")
	if err != nil {
		t.Fatalf("build ip template: %v", err)
	}
	var call atomic.Uint32
	session := func() *coreSession {
		s := newTestCoreSession(msess.CoreSession{
			Options: ClientOptions{
			DataplaneMode: option.MasqueDataplaneConnectIP,
			MasqueEffectiveHTTPLayer: option.MasqueHTTPLayerH3,
		},
			TemplateIP: templateIP,
			Caps: CapabilitySet{ConnectIP: true},
			HTTPLayerAuto: true,
		})
		cs := &coreSession{CoreSession: s.CoreSession, 	dialConnectIPAttemptHook: func(ctx context.Context, useHTTP2 bool) (*connectip.Conn, error) {
			n := call.Add(1)
			if useHTTP2 {
				return nil, errors.New("stub h2 connect-ip after overlay switch")
			}
			switch n {
			case 1:
				return nil, errors.New("nonswitchable_stub_connect_ip_1")
			case 2:
				return nil, errors.New("Extended CONNECT not supported on this path")
			default:
				return nil, errors.New("unexpected extra connect_ip dial on h3")
			}
		}}
		return cs
	}()
	session.UDPHTTPLayer.Store(option.MasqueHTTPLayerH3)

	_, openErr := session.OpenIPSession(context.Background())
	if openErr == nil {
		t.Fatal("expected error when h2 connect-ip dial is stubbed to fail")
	}
	if session.currentUDPHTTPLayer() != option.MasqueHTTPLayerH2 {
		t.Fatalf("expected http_layer fallback after iph3 reconnect switchable failure, overlay=%q", session.currentUDPHTTPLayer())
	}
	// 2Г— H3 (nonswitchable + after ipHTTP churn), 1Г— H3в†’H2 fallback dial, 1Г— H2 transport churn redial.
	if call.Load() != 4 {
		t.Fatalf("expected four connect_ip stub invocations, got %d", call.Load())
	}
}

func TestOpenIPSessionH2TransportChurnBeforeHopPivot(t *testing.T) {
	templateIP, err := uritemplate.New("https://example.com/masque/ip")
	if err != nil {
		t.Fatalf("build ip template: %v", err)
	}
	okConn := testStubConnectIPConn()
	var call atomic.Uint32
	session := func() *coreSession {
		s := newTestCoreSession(msess.CoreSession{
			Options: ClientOptions{
			DataplaneMode: option.MasqueDataplaneConnectIP,
			MasqueEffectiveHTTPLayer: option.MasqueHTTPLayerH2,
			TCPDial: func(ctx context.Context, network, address string) (net.Conn, error) {
				return nil, errors.New("tcp dial stub")
			},
		},
			TemplateIP: templateIP,
			Caps: CapabilitySet{ConnectIP: true},
		})
		cs := &coreSession{CoreSession: s.CoreSession, 	dialConnectIPAttemptHook: func(ctx context.Context, useHTTP2 bool) (*connectip.Conn, error) {
			if !useHTTP2 {
				t.Fatal("expected CONNECT-IP dial on h2 overlay only")
			}
			n := call.Add(1)
			switch n {
			case 1:
				return nil, errors.New("nonswitchable_stub_connect_ip_h2_1")
			case 2:
				return okConn, nil
			default:
				return nil, errors.New("unexpected extra connect_ip dial on h2")
			}
		}}
		return cs
	}()
	session.UDPHTTPLayer.Store(option.MasqueHTTPLayerH2)

	sess, openErr := session.OpenIPSession(context.Background())
	if openErr != nil {
		t.Fatalf("open ip session: %v", openErr)
	}
	if call.Load() != 2 {
		t.Fatalf("expected h2 churn then success (2 connect-ip attempts), got %d", call.Load())
	}
	ps, ok := sess.(*mcip.ClientPacketSession)
	if !ok || ps.Conn() != okConn {
		t.Fatalf("unexpected session wrapper: %T / conn=%v", sess, ps)
	}
}

func TestDialConnectIPHTTP2ReturnsCanceledBeforeTCPConfig(t *testing.T) {
	templateIP, err := uritemplate.New("https://example.com/masque/ip")
	if err != nil {
		t.Fatalf("build ip template: %v", err)
	}
	s := newTestCoreSession(msess.CoreSession{
			Options: ClientOptions{
			Tag:    "t",
			Server: "127.0.0.1",
			// Intentionally no TCPDial: a canceled dial must not surface as missing dialer before ctx cause.
			ServerPort: 443,
		},
			TemplateIP: templateIP,
		})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, dialErr := s.dialConnectIPHTTP2(ctx)
	if dialErr == nil {
		t.Fatal("expected error")
	}
	if !errors.Is(dialErr, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", dialErr)
	}
}

func TestDialConnectIPHTTP2ReturnsErrWhenTemplateNil(t *testing.T) {
	s := newTestCoreSession(msess.CoreSession{
			Options: ClientOptions{
			Tag:        "t",
			Server:     "127.0.0.1",
			ServerPort: 443,
			TCPDial: func(context.Context, string, string) (net.Conn, error) {
				return nil, errors.New("unreachable tcp dial")
			},
		},
			TemplateIP: nil,
		})
	_, dialErr := s.dialConnectIPHTTP2(context.Background())
	if dialErr == nil {
		t.Fatal("expected error")
	}
	if !errors.Is(dialErr, msess.ErrConnectIPTemplateNotConfigured) {
		t.Fatalf("unexpected err: %v", dialErr)
	}
	if httpx.IsLayerSwitchableFailure(dialErr) {
		t.Fatal("missing IP template must not imply http_layer_fallback")
	}
}

func TestDialUDPOverHTTP2ReturnsCanceledBeforeTCPConfig(t *testing.T) {
	templateUDP, err := uritemplate.New("https://example.com/masque/udp/{target_host}/{target_port}")
	if err != nil {
		t.Fatalf("build udp template: %v", err)
	}
	s := newTestCoreSession(msess.CoreSession{
			Options: ClientOptions{
			Tag:        "t",
			Server:     "127.0.0.1",
			ServerPort: 443,
			// No TCPDial: canceled ctx must yield Cause before tcp dialer error.
		},
		})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, dialErr := s.dialUDPOverHTTP2(ctx, templateUDP, "8.8.8.8:53")
	if dialErr == nil {
		t.Fatal("expected error")
	}
	if !errors.Is(dialErr, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", dialErr)
	}
}

func TestDialUDPOverHTTP2ReturnsErrWhenTemplateNil(t *testing.T) {
	s := newTestCoreSession(msess.CoreSession{
			Options: ClientOptions{
			Tag:        "t",
			Server:     "127.0.0.1",
			ServerPort: 443,
		},
		})
	_, dialErr := s.dialUDPOverHTTP2(context.Background(), nil, "8.8.8.8:53")
	if dialErr == nil {
		t.Fatal("expected error")
	}
	if !errors.Is(dialErr, msess.ErrConnectUDPTemplateNotConfigured) {
		t.Fatalf("unexpected err: %v", dialErr)
	}
	if httpx.IsLayerSwitchableFailure(dialErr) {
		t.Fatal("nil template is a config error; must not imply http_layer_fallback")
	}
}

func TestDialUDPAddrH3ReturnsErrWhenTemplateNil(t *testing.T) {
	s := newTestCoreSession(msess.CoreSession{
			Options: ClientOptions{
			Tag:        "t",
			Server:     "127.0.0.1",
			ServerPort: 443,
		},
		})
	s.UDPHTTPLayer.Store(option.MasqueHTTPLayerH3)
	cli := &qmasque.Client{}
	_, dialErr := s.dialUDPAddr(context.Background(), cli, nil, "8.8.8.8:53")
	if dialErr == nil {
		t.Fatal("expected error")
	}
	if !errors.Is(dialErr, msess.ErrConnectUDPTemplateNotConfigured) {
		t.Fatalf("unexpected err: %v", dialErr)
	}
	if httpx.IsLayerSwitchableFailure(dialErr) {
		t.Fatal("nil template is a config error; must not imply http_layer_fallback")
	}
}

func TestDialUDPAddrH2ReturnsErrWhenTemplateNil(t *testing.T) {
	s := newTestCoreSession(msess.CoreSession{
			Options: ClientOptions{
			Tag:        "t",
			Server:     "127.0.0.1",
			ServerPort: 443,
			TCPDial: func(context.Context, string, string) (net.Conn, error) {
				return nil, errors.New("unreachable tcp dial")
			},
		},
		})
	s.UDPHTTPLayer.Store(option.MasqueHTTPLayerH2)
	s.h2UDPConnectHook = func(context.Context, *uritemplate.Template, string) (net.PacketConn, error) {
		t.Fatal("dialUDPOverHTTP2 hook must not run when UDP template is nil")
		return nil, nil
	}
	_, dialErr := s.dialUDPAddr(context.Background(), nil, nil, "8.8.8.8:53")
	if dialErr == nil {
		t.Fatal("expected error")
	}
	if !errors.Is(dialErr, msess.ErrConnectUDPTemplateNotConfigured) {
		t.Fatalf("unexpected err: %v", dialErr)
	}
	if httpx.IsLayerSwitchableFailure(dialErr) {
		t.Fatal("nil template is a config error; must not imply http_layer_fallback")
	}
}

func TestDialTCPStreamH2ReturnsCanceledBeforeTCPConfig(t *testing.T) {
	u, err := url.Parse("https://example.com/masque/tcp")
	if err != nil {
		t.Fatalf("parse tcp url: %v", err)
	}
	opts := ClientOptions{
		Tag:        "t",
		Server:     "127.0.0.1",
		ServerPort: 443,
	}
	s := newTestCoreSession(msess.CoreSession{
			Options: opts,
		})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, dialErr := s.dialTCPStreamH2(ctx, u, opts, "example.com", M.Socksaddr{})
	if dialErr == nil {
		t.Fatal("expected error")
	}
	if !errors.Is(dialErr, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", dialErr)
	}
	if !errors.Is(dialErr, msess.ErrTCPConnectStreamFailed) {
		t.Fatalf("expected msess.ErrTCPConnectStreamFailed joined, got %v", dialErr)
	}
}

// H2 CONNECT-stream must join msess.ErrTCPConnectStreamFailed for early transport failures (parity with H3 and with in-loop errors).
func TestDialTCPStreamH2JoinsErrWhenH2TransportUnconfigured(t *testing.T) {
	u, err := url.Parse("https://example.com/masque/tcp/example.com/443")
	if err != nil {
		t.Fatalf("parse tcp url: %v", err)
	}
	opts := ClientOptions{
		Tag:        "t",
		Server:     "127.0.0.1",
		ServerPort: 443,
	}
	s := newTestCoreSession(msess.CoreSession{
			Options: opts,
		})
	_, dialErr := s.dialTCPStreamH2(context.Background(), u, opts, "example.com", M.Socksaddr{Port: 443})
	if dialErr == nil {
		t.Fatal("expected error")
	}
	if !errors.Is(dialErr, msess.ErrTCPConnectStreamFailed) {
		t.Fatalf("expected msess.ErrTCPConnectStreamFailed joined, got %v", dialErr)
	}
	if !strings.Contains(dialErr.Error(), "tcp dialer is not configured") {
		t.Fatalf("expected tcp dialer error substring, got %v", dialErr)
	}
}

func TestDialTCPStreamH2ReturnsCanceledAfterRoundTripSuccess(t *testing.T) {
	u, err := url.Parse("https://example.com/masque/tcp")
	if err != nil {
		t.Fatalf("parse tcp url: %v", err)
	}
	opts := ClientOptions{
		Tag:        "t",
		Server:     "127.0.0.1",
		ServerPort: 443,
		TCPDial: func(context.Context, string, string) (net.Conn, error) {
			return nil, errors.New("unexpected tcp dial")
		},
	}
	s := newTestCoreSession(msess.CoreSession{
			Options: opts,
		})
	var attempts atomic.Uint32
	ctx, cancel := context.WithCancel(context.Background())
	s.TCPRoundTripper = roundTripperFunc(func(*http.Request) (*http.Response, error) {
		attempts.Add(1)
		cancel()
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader("")),
			Header:     make(http.Header),
		}, nil
	})
	_, dialErr := s.dialTCPStreamH2(ctx, u, opts, "example.com", M.Socksaddr{Port: 443})
	if dialErr == nil {
		t.Fatal("expected canceled error")
	}
	if !errors.Is(dialErr, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", dialErr)
	}
	if !errors.Is(dialErr, msess.ErrTCPConnectStreamFailed) {
		t.Fatalf("expected msess.ErrTCPConnectStreamFailed joined, got %v", dialErr)
	}
	if got := attempts.Load(); got != 1 {
		t.Fatalf("expected single RoundTrip attempt, got %d", got)
	}
}

func TestDialTCPStreamH2StopsFailedRequestRelayBeforeRetry(t *testing.T) {
	u, err := url.Parse("https://example.com/masque/tcp")
	if err != nil {
		t.Fatalf("parse tcp url: %v", err)
	}
	opts := ClientOptions{
		Tag:        "t",
		Server:     "127.0.0.1",
		ServerPort: 443,
		TCPDial: func(context.Context, string, string) (net.Conn, error) {
			return nil, errors.New("unexpected tcp dial")
		},
	}
	s := newTestCoreSession(msess.CoreSession{
			Options: opts,
		})
	var attempts atomic.Uint32
	var activeRelays atomic.Int32
	prevFactory := h2ConnectRequestContextFactory
	h2ConnectRequestContextFactory = func(parent context.Context) (context.Context, func(detach bool)) {
		reqCtx, stop := connectip.NewH2ExtendedConnectRequestContext(parent)
		if n := activeRelays.Add(1); n > 1 {
			t.Fatalf("request relay from previous attempt is still active: %d", n)
		}
		return reqCtx, func(detach bool) {
			stop(detach)
			activeRelays.Add(-1)
		}
	}
	t.Cleanup(func() {
		h2ConnectRequestContextFactory = prevFactory
		if n := activeRelays.Load(); n != 0 {
			t.Fatalf("request relay leaks after dial return: %d", n)
		}
	})
	s.TCPRoundTripper = roundTripperFunc(func(*http.Request) (*http.Response, error) {
		if attempts.Add(1) == 1 {
			return nil, errors.New("broken pipe")
		}
		return nil, errors.New("permanent failure")
	})

	_, dialErr := s.dialTCPStreamH2(context.Background(), u, opts, "example.com", M.Socksaddr{Port: 443})
	if dialErr == nil {
		t.Fatal("expected dial error")
	}
	if got := attempts.Load(); got != 2 {
		t.Fatalf("expected two RoundTrip attempts, got %d", got)
	}
}

// Parity with dialUDPOverHTTP2 / dialConnectIPHTTP2 / dialTCPStreamH2: no masque_http_layer_attempt when ctx is already canceled.
func TestDialUDPAddrH3ReturnsCanceledBeforeLayerLog(t *testing.T) {
	templateUDP, err := uritemplate.New("https://example.com/masque/udp/{target_host}/{target_port}")
	if err != nil {
		t.Fatalf("build udp template: %v", err)
	}
	s := newTestCoreSession(msess.CoreSession{
			Options: ClientOptions{
			Tag:        "t",
			Server:     "127.0.0.1",
			ServerPort: 443,
		},
		})
	s.UDPHTTPLayer.Store(option.MasqueHTTPLayerH3)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, dialErr := s.dialUDPAddr(ctx, nil, templateUDP, "8.8.8.8:53")
	if dialErr == nil {
		t.Fatal("expected error")
	}
	if !errors.Is(dialErr, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", dialErr)
	}
}

// Parity with TestDialUDPAddrH3ReturnsCanceledBeforeLayerLog: canceled ctx returns before masque_http_layer_attempt
// and before invoking dialUDPOverHTTP2 (no overlay entry).
func TestDialUDPAddrH2ReturnsCanceledBeforeDialUDPOverHTTP2(t *testing.T) {
	templateUDP, err := uritemplate.New("https://example.com/masque/udp/{target_host}/{target_port}")
	if err != nil {
		t.Fatalf("build udp template: %v", err)
	}
	s := newTestCoreSession(msess.CoreSession{
			Options: ClientOptions{
			Tag:        "t",
			Server:     "127.0.0.1",
			ServerPort: 443,
			TCPDial: func(context.Context, string, string) (net.Conn, error) {
				return nil, errors.New("unreachable tcp dial")
			},
		},
		})
	s.h2UDPConnectHook = func(context.Context, *uritemplate.Template, string) (net.PacketConn, error) {
		t.Fatal("dialUDPOverHTTP2 path should not run when ctx already canceled")
		return nil, nil
	}
	s.UDPHTTPLayer.Store(option.MasqueHTTPLayerH2)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, dialErr := s.dialUDPAddr(ctx, nil, templateUDP, "8.8.8.8:53")
	if dialErr == nil {
		t.Fatal("expected error")
	}
	if !errors.Is(dialErr, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", dialErr)
	}
}

func TestDialConnectIPAttemptH3ReturnsErrWhenTemplateNil(t *testing.T) {
	s := newTestCoreSession(msess.CoreSession{
			Options: ClientOptions{
			Tag:        "t",
			Server:     "127.0.0.1",
			ServerPort: 443,
		},
			TemplateIP: nil,
		})
	_, dialErr := s.dialConnectIPAttempt(context.Background(), false)
	if dialErr == nil {
		t.Fatal("expected error")
	}
	if !errors.Is(dialErr, msess.ErrConnectIPTemplateNotConfigured) {
		t.Fatalf("unexpected err: %v", dialErr)
	}
	if httpx.IsLayerSwitchableFailure(dialErr) {
		t.Fatal("missing IP template must not imply http_layer_fallback")
	}
}

func TestDialConnectIPAttemptH3ReturnsCanceledBeforeLayerLog(t *testing.T) {
	templateIP, err := uritemplate.New("https://example.com/masque/ip")
	if err != nil {
		t.Fatalf("build ip template: %v", err)
	}
	s := newTestCoreSession(msess.CoreSession{
			Options: ClientOptions{
			Tag:        "t",
			Server:     "127.0.0.1",
			ServerPort: 443,
		},
			TemplateIP: templateIP,
		})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, dialErr := s.dialConnectIPAttempt(ctx, false)
	if dialErr == nil {
		t.Fatal("expected error")
	}
	if !errors.Is(dialErr, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", dialErr)
	}
}

// Parity with the H3 branch of dialConnectIPAttempt: canceled ctx clears http_layer_fallback latch before any H2 CONNECT-IP work.
func TestDialConnectIPAttemptH2ReturnsCanceledBeforeLayerWorkClearsFallbackLatch(t *testing.T) {
	templateIP, err := uritemplate.New("https://example.com/masque/ip")
	if err != nil {
		t.Fatalf("build ip template: %v", err)
	}
	s := newTestCoreSession(msess.CoreSession{
			Options: ClientOptions{
			Tag:        "t",
			Server:     "127.0.0.1",
			ServerPort: 443,
			TCPDial: func(context.Context, string, string) (net.Conn, error) {
				t.Fatal("TCPDial must not run when ctx already canceled before CONNECT-IP H2 dial")
				return nil, nil
			},
		},
			TemplateIP: templateIP,
		})
	s.HTTPFallbackConsumed.Store(true)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, dialErr := s.dialConnectIPAttempt(ctx, true)
	if dialErr == nil {
		t.Fatal("expected error")
	}
	if !errors.Is(dialErr, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", dialErr)
	}
	if s.HTTPFallbackConsumed.Load() {
		t.Fatal("expected httpFallbackConsumed cleared on early cancel before H2 CONNECT-IP (parity with H3)")
	}
}

// Parity with openIPSessionLocked: cached HTTP/3 client conn must not short-circuit a canceled ctx.
func TestOpenHTTP3ClientConnReturnsCanceledBeforeReuse(t *testing.T) {
	s := newTestCoreSession(msess.CoreSession{
			Options: ClientOptions{
			Tag:        "t",
			Server:     "127.0.0.1",
			ServerPort: 443,
		},
			IPHTTPConn: new(http3.ClientConn),
		})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	conn, openErr := s.openHTTP3ClientConn(ctx)
	if openErr == nil {
		t.Fatal("expected error")
	}
	if conn != nil {
		t.Fatal("expected nil conn")
	}
	if !errors.Is(openErr, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", openErr)
	}
}

func TestEnsureH2UDPTransportSetsDisableCompression(t *testing.T) {
	ctx := context.Background()
	s := newTestCoreSession(msess.CoreSession{
		Options: ClientOptions{
			Server: "example.com",
			TCPDial: func(context.Context, string, string) (net.Conn, error) {
				return nil, errors.New("dial not used in this test")
			},
		},
	})
	tr, err := s.ensureH2UDPTransport(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !tr.DisableCompression {
		t.Fatal("H2 MASQUE dataplane must not negotiate gzip (breaks CONNECT stream framing)")
	}
	tr2, err := s.ensureH2UDPTransport(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if tr2 != tr {
		t.Fatal("expected cached H2 UDP transport reuse")
	}
	if !tr2.DisableCompression {
		t.Fatal("expected DisableCompression on reused transport")
	}
}

// Parity with openHTTP3ClientConn: cached HTTP/2 overlay transport must not short-circuit a canceled ctx.
func TestEnsureH2UDPTransportReturnsCanceledBeforeReuse(t *testing.T) {
	s := newTestCoreSession(msess.CoreSession{
			Options: ClientOptions{
			Tag:        "t",
			Server:     "127.0.0.1",
			ServerPort: 443,
			TCPDial: func(context.Context, string, string) (net.Conn, error) {
				return nil, errors.New("unreachable")
			},
		},
			H2UDPTransport: &http2.Transport{},
		})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	tr, err := s.ensureH2UDPTransport(ctx)
	if err == nil {
		t.Fatal("expected error")
	}
	if tr != nil {
		t.Fatal("expected nil transport")
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
}

// Parity with dial paths: a canceled ctx must not hit the reuse shortcut (success with existing ipConn).
func TestOpenIPSessionLockedReturnsCanceledBeforeReuse(t *testing.T) {
	s := newTestCoreSession(msess.CoreSession{
			Options: ClientOptions{Tag: "t"},
			Caps: CapabilitySet{ConnectIP: true},
			IPConn: testStubConnectIPConn(),
		})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	s.Mu.Lock()
	_, openErr := s.openIPSessionLocked(ctx)
	s.Mu.Unlock()
	if openErr == nil {
		t.Fatal("expected error")
	}
	if !errors.Is(openErr, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", openErr)
	}
}

// CONNECT-IP dial failure caused by ctx cancellation must not call advanceHop (multi-hop chain).
func TestOpenIPSessionLockedCanceledDialDoesNotAdvanceHop(t *testing.T) {
	templateIP, err := uritemplate.New("https://hop1.example/masque/ip")
	if err != nil {
		t.Fatalf("template: %v", err)
	}
	s := newTestCoreSession(msess.CoreSession{
			Options: ClientOptions{
			Tag:        "t",
			Server:     "hop1.example",
			ServerPort: 443,
			Hops: []HopOptions{
				{Tag: "h1", Server: "hop1.example", Port: 443},
				{Tag: "h2", Via: "h1", Server: "hop2.example", Port: 8443},
			},
		},
			HopOrder: []HopOptions{
			{Tag: "h1", Server: "hop1.example", Port: 443},
			{Tag: "h2", Via: "h1", Server: "hop2.example", Port: 8443},
		},
			HopIndex: 0,
			Caps: CapabilitySet{ConnectIP: true},
			TemplateIP: templateIP,
		})
	// Block until ctx is canceled, then return cancellation (simulates long CONNECT-IP / QUIC handshake).
	// dialConnectIPOnCurrentHopLocked may call the hook multiple times on one hop; only the first entry signals the test goroutine.
	entered := make(chan struct{})
	var enteredOnce sync.Once
	s.dialConnectIPAttemptHook = func(ctx context.Context, _ bool) (*connectip.Conn, error) {
		enteredOnce.Do(func() { close(entered) })
		<-ctx.Done()
		return nil, context.Cause(ctx)
	}
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		<-entered
		cancel()
	}()
	s.Mu.Lock()
	_, openErr := s.openIPSessionLocked(ctx)
	s.Mu.Unlock()
	if openErr == nil {
		t.Fatal("expected error")
	}
	if !errors.Is(openErr, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", openErr)
	}
	if s.HopIndex != 0 {
		t.Fatalf("expected hopIndex to stay 0 on cancel, got %d", s.HopIndex)
	}
	if s.Options.Server != "hop1.example" || s.Options.ServerPort != 443 {
		t.Fatalf("expected session to remain on first hop, got %s:%d", s.Options.Server, s.Options.ServerPort)
	}
}

// After a non-cancel failure on the entry hop, cancellation on a subsequent inner-hop CONNECT-IP dial
// must return before the next advanceHop() consumes another chain entry.
func TestOpenIPSessionLockedCanceledDialInnerLoopDoesNotAdvanceHopAgain(t *testing.T) {
	templateIP, err := uritemplate.New("https://hop1.example/masque/ip")
	if err != nil {
		t.Fatalf("template: %v", err)
	}
	s := newTestCoreSession(msess.CoreSession{
			Options: ClientOptions{
			Tag:        "t",
			Server:     "hop1.example",
			ServerPort: 443,
			Hops: []HopOptions{
				{Tag: "h1", Server: "hop1.example", Port: 443},
				{Tag: "h2", Via: "h1", Server: "hop2.example", Port: 8443},
				{Tag: "h3", Via: "h2", Server: "hop3.example", Port: 8444},
			},
		},
			HopOrder: []HopOptions{
			{Tag: "h1", Server: "hop1.example", Port: 443},
			{Tag: "h2", Via: "h1", Server: "hop2.example", Port: 8443},
			{Tag: "h3", Via: "h2", Server: "hop3.example", Port: 8444},
		},
			HopIndex: 0,
			Caps: CapabilitySet{ConnectIP: true},
			TemplateIP: templateIP,
		})
	secondDialEntered := make(chan struct{})
	var enteredOnce sync.Once
	ctx, cancel := context.WithCancel(context.Background())
	s.dialConnectIPAttemptHook = func(dialCtx context.Context, _ bool) (*connectip.Conn, error) {
		if s.HopIndex == 0 {
			return nil, errors.New("overlay handshake failed")
		}
		enteredOnce.Do(func() { close(secondDialEntered) })
		<-dialCtx.Done()
		return nil, context.Cause(dialCtx)
	}
	go func() {
		<-secondDialEntered
		cancel()
	}()
	s.Mu.Lock()
	_, openErr := s.openIPSessionLocked(ctx)
	s.Mu.Unlock()
	if openErr == nil {
		t.Fatal("expected error")
	}
	if !errors.Is(openErr, context.Canceled) {
		t.Fatalf("expected context.Canceled in error chain, got %v", openErr)
	}
	if s.HopIndex != 1 {
		t.Fatalf("expected exactly one hop advance before cancel, hopIndex=%d", s.HopIndex)
	}
	if s.Options.Server != "hop2.example" || s.Options.ServerPort != 8443 {
		t.Fatalf("expected logical hop h2 after single advance, got %s:%d", s.Options.Server, s.Options.ServerPort)
	}
}

func TestDialTCPStreamHTTP3ReturnsCanceledBeforeLayerLog(t *testing.T) {
	u, err := url.Parse("https://example.com/masque/tcp")
	if err != nil {
		t.Fatalf("parse tcp url: %v", err)
	}
	opts := ClientOptions{
		Tag:        "t",
		Server:     "127.0.0.1",
		ServerPort: 443,
	}
	s := newTestCoreSession(msess.CoreSession{
			Options: opts,
		})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, dialErr := s.dialTCPStreamHTTP3(ctx, u, opts, "example.com", 80, nil)
	if dialErr == nil {
		t.Fatal("expected error")
	}
	if !errors.Is(dialErr, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", dialErr)
	}
	if !errors.Is(dialErr, msess.ErrTCPConnectStreamFailed) {
		t.Fatalf("expected msess.ErrTCPConnectStreamFailed joined, got %v", dialErr)
	}
}

// Parity with dialTCPStreamH2: cancel during RoundTrip success must not surface a CONNECT-stream conn.
func TestDialTCPStreamHTTP3ReturnsCanceledAfterRoundTripSuccess(t *testing.T) {
	u, err := url.Parse("https://example.com/masque/tcp")
	if err != nil {
		t.Fatalf("parse tcp url: %v", err)
	}
	opts := ClientOptions{
		Tag:        "t",
		Server:     "127.0.0.1",
		ServerPort: 443,
	}
	s := newTestCoreSession(msess.CoreSession{
			Options: opts,
		})
	var attempts atomic.Uint32
	ctx, cancel := context.WithCancel(context.Background())
	s.TCPRoundTripper = roundTripperFunc(func(*http.Request) (*http.Response, error) {
		attempts.Add(1)
		cancel()
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader("")),
			Header:     make(http.Header),
		}, nil
	})
	_, dialErr := s.dialTCPStreamHTTP3(ctx, u, opts, "example.com", 443, nil)
	if dialErr == nil {
		t.Fatal("expected canceled error")
	}
	if !errors.Is(dialErr, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", dialErr)
	}
	if !errors.Is(dialErr, msess.ErrTCPConnectStreamFailed) {
		t.Fatalf("expected msess.ErrTCPConnectStreamFailed joined, got %v", dialErr)
	}
	if got := attempts.Load(); got != 1 {
		t.Fatalf("expected single RoundTrip attempt, got %d", got)
	}
}

// CONNECT-IP ListenPacket only needs a working openIPSession; the SOCKS-style destination is used
// on the CONNECT-UDP path. Resolving it first incorrectly rejected zero/invalid metadata.
func TestListenPacketConnectIPSkipsDestinationResolution(t *testing.T) {
	var dest M.Socksaddr
	if _, err := resolveDestinationHost(dest); err == nil {
		t.Fatal("test requires invalid destination")
	}
	templateIP, err := uritemplate.New("https://example.com/masque/ip")
	if err != nil {
		t.Fatalf("build ip template: %v", err)
	}
	okConn := testStubConnectIPConn()
	session := func() *coreSession {
		s := newTestCoreSession(msess.CoreSession{
			Options: ClientOptions{
			DataplaneMode: option.MasqueDataplaneConnectIP,
		},
			TemplateIP: templateIP,
			Caps: CapabilitySet{ConnectIP: true},
		})
		cs := &coreSession{CoreSession: s.CoreSession, 	dialConnectIPAttemptHook: func(ctx context.Context, useHTTP2 bool) (*connectip.Conn, error) {
			return okConn, nil
		}}
		return cs
	}()
	session.UDPHTTPLayer.Store(option.MasqueHTTPLayerH3)

	pc, listenErr := session.ListenPacket(context.Background(), dest)
	if listenErr != nil {
		t.Fatalf("ListenPacket: %v", listenErr)
	}
	if pc == nil {
		t.Fatal("expected non-nil PacketConn")
	}
	_ = pc.Close()
}

func TestListenPacketConnectIPCanceledBeforeNewConnectIPUDPPacketConn(t *testing.T) {
	templateIP, err := uritemplate.New("https://example.com/masque/ip")
	if err != nil {
		t.Fatalf("build ip template: %v", err)
	}
	okConn := testStubConnectIPConn()
	ctx, cancel := context.WithCancel(context.Background())
	session := func() *coreSession {
		s := newTestCoreSession(msess.CoreSession{
			Options: ClientOptions{
			DataplaneMode: option.MasqueDataplaneConnectIP,
		},
			TemplateIP: templateIP,
			Caps: CapabilitySet{ConnectIP: true},
		})
		cs := &coreSession{CoreSession: s.CoreSession, 	dialConnectIPAttemptHook: func(context.Context, bool) (*connectip.Conn, error) {
			return okConn, nil
		}, 	listenPacketPostOpenIPSessionUnlockHook: func() { cancel() }}
		return cs
	}()
	session.UDPHTTPLayer.Store(option.MasqueHTTPLayerH3)
	// Exercise full abandon teardown: overlay transports must not outlive the closed connect-ip.Conn.
	session.IPHTTP = &http3.Transport{}
	session.H2UDPMu.Lock()
	session.H2UDPTransport = &http2.Transport{}
	session.H2UDPMu.Unlock()

	_, listenErr := session.ListenPacket(ctx, M.Socksaddr{})
	if listenErr == nil || !errors.Is(listenErr, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", listenErr)
	}
	if session.IPConn != nil {
		t.Fatal("expected released ipConn after cancel before PacketConn wrap")
	}
	if session.IPHTTP != nil || session.IPHTTPConn != nil {
		t.Fatal("expected resetIPH3 after abandon before PacketConn wrap")
	}
	session.H2UDPMu.Lock()
	h2Left := session.H2UDPTransport
	session.H2UDPMu.Unlock()
	if h2Left != nil {
		t.Fatal("expected H2 overlay pool cleared after abandon before PacketConn wrap")
	}
}

func TestReleaseOpenedConnectIPSessionIfAbandonedClearsHTTPLayers(t *testing.T) {
	s := newTestCoreSession(msess.CoreSession{
			Options: ClientOptions{},
		})
	s.IPConn = testStubConnectIPConn()
	s.IPHTTP = &http3.Transport{}
	s.H2UDPMu.Lock()
	s.H2UDPTransport = &http2.Transport{}
	s.H2UDPMu.Unlock()

	s.releaseOpenedConnectIPSessionIfAbandoned()

	if s.IPConn != nil || s.IPHTTP != nil || s.IPHTTPConn != nil {
		t.Fatalf("expected CONNECT-IP plane and HTTP/3 refs cleared, ipConn=%v ipHTTP=%v", s.IPConn, s.IPHTTP)
	}
	s.H2UDPMu.Lock()
	h2Left := s.H2UDPTransport
	s.H2UDPMu.Unlock()
	if h2Left != nil {
		t.Fatal("expected h2UdpTransport cleared")
	}
}

func TestListenPacketConnectIPCanceledBeforeOpenIPSessions(t *testing.T) {
	var hookCalls atomic.Uint32
	okConn := testStubConnectIPConn()
	session := func() *coreSession {
		s := newTestCoreSession(msess.CoreSession{
			Options: ClientOptions{DataplaneMode: option.MasqueDataplaneConnectIP},
			Caps: CapabilitySet{ConnectIP: true},
		})
		cs := &coreSession{CoreSession: s.CoreSession, 	dialConnectIPAttemptHook: func(context.Context, bool) (*connectip.Conn, error) {
			hookCalls.Add(1)
			return okConn, nil
		}}
		return cs
	}()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, listenErr := session.ListenPacket(ctx, M.Socksaddr{})
	if listenErr == nil || !errors.Is(listenErr, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", listenErr)
	}
	if hookCalls.Load() != 0 {
		t.Fatalf("connect-ip dial hook invoked %d times", hookCalls.Load())
	}
}

func TestOpenIPSessionCanceledBeforeLockSkipsConnectIPDial(t *testing.T) {
	var hookCalls atomic.Uint32
	okConn := testStubConnectIPConn()
	session := func() *coreSession {
		s := newTestCoreSession(msess.CoreSession{
			Options: ClientOptions{DataplaneMode: option.MasqueDataplaneConnectIP},
			Caps: CapabilitySet{ConnectIP: true},
		})
		cs := &coreSession{CoreSession: s.CoreSession, 	dialConnectIPAttemptHook: func(context.Context, bool) (*connectip.Conn, error) {
			hookCalls.Add(1)
			return okConn, nil
		}}
		return cs
	}()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, openErr := session.OpenIPSession(ctx)
	if openErr == nil || !errors.Is(openErr, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", openErr)
	}
	if hookCalls.Load() != 0 {
		t.Fatalf("connect-ip dial hook invoked %d times", hookCalls.Load())
	}
}

func TestListenPacketCanceledSkipsUDPDialHook(t *testing.T) {
	templateUDP, err := uritemplate.New("https://example.com/masque/udp/{target_host}/{target_port}")
	if err != nil {
		t.Fatalf("build udp template: %v", err)
	}
	var dials atomic.Uint32
	s := func() *coreSession {
		s := newTestCoreSession(msess.CoreSession{
			Options: ClientOptions{
		},
			UDPClient: &qmasque.Client{},
			TemplateUDP: templateUDP,
			Caps: CapabilitySet{ConnectUDP: true},
		})
		cs := &coreSession{CoreSession: s.CoreSession, 	udpDial: func(context.Context, *qmasque.Client, *uritemplate.Template, string) (net.PacketConn, error) {
			dials.Add(1)
			return nil, errors.New("unexpected dial")
		}}
		return cs
	}()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, listenErr := s.ListenPacket(ctx, M.ParseSocksaddrHostPort("127.0.0.1", 53))
	if listenErr == nil || !errors.Is(listenErr, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", listenErr)
	}
	if dials.Load() != 0 {
		t.Fatalf("udpDial called %d times", dials.Load())
	}
}

func TestListenPacketConnectUDPCanceledBeforeResolveDestination(t *testing.T) {
	templateUDP, err := uritemplate.New("https://example.com/masque/udp/{target_host}/{target_port}")
	if err != nil {
		t.Fatalf("build udp template: %v", err)
	}
	var dials atomic.Uint32
	ctx, cancel := context.WithCancel(context.Background())
	s := func() *coreSession {
		s := newTestCoreSession(msess.CoreSession{
			Options: ClientOptions{
		},
			UDPClient: &qmasque.Client{},
			TemplateUDP: templateUDP,
			Caps: CapabilitySet{ConnectUDP: true},
		})
		cs := &coreSession{CoreSession: s.CoreSession, 	udpDial: func(context.Context, *qmasque.Client, *uritemplate.Template, string) (net.PacketConn, error) {
			dials.Add(1)
			return nil, errors.New("unexpected dial")
		}, 	listenPacketPreResolveDestinationHook: func() { cancel() }}
		return cs
	}()
	_, listenErr := s.ListenPacket(ctx, M.ParseSocksaddrHostPort("127.0.0.1", 53))
	if listenErr == nil || !errors.Is(listenErr, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", listenErr)
	}
	if dials.Load() != 0 {
		t.Fatalf("udpDial called %d times", dials.Load())
	}
}

func TestDialContextCanceledBeforeTCPBranches(t *testing.T) {
	s := newTestCoreSession(msess.CoreSession{
			Options: ClientOptions{
		},
		})
	s.HTTPFallbackConsumed.Store(true)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := s.DialContext(ctx, "tcp", M.ParseSocksaddrHostPort("127.0.0.1", 443))
	if err == nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
	if s.HTTPFallbackConsumed.Load() {
		t.Fatal("expected httpFallbackConsumed cleared on early cancel before dialTCPStream (parity with ListenPacket/OpenIPSession)")
	}
}

func TestDialConnectIPTCPCanceledClearsHTTPFallbackLatch(t *testing.T) {
	s := newTestCoreSession(msess.CoreSession{
			Caps: CapabilitySet{ConnectIP: true},
			Options: ClientOptions{
			DataplaneMode: option.MasqueDataplaneConnectIP,
			Server:        "127.0.0.1",
			ServerPort:    443,
		},
		})
	s.HTTPFallbackConsumed.Store(true)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := s.dialConnectIPTCP(ctx, M.ParseSocksaddrHostPort("127.0.0.1", 443))
	if err == nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
	if s.HTTPFallbackConsumed.Load() {
		t.Fatal("expected httpFallbackConsumed cleared on early cancel in dialConnectIPTCP (parity with DialContext/ListenPacket)")
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
	session := func() *coreSession {
		s := newTestCoreSession(msess.CoreSession{
			Options: ClientOptions{
		},
			UDPClient: &qmasque.Client{},
			TemplateUDP: templateUDP,
			Caps: CapabilitySet{ConnectUDP: true, ConnectIP: false},
		})
		cs := &coreSession{CoreSession: s.CoreSession, 	udpDial: func(ctx context.Context, client *qmasque.Client, template *uritemplate.Template, target string) (net.PacketConn, error) {
			if startOnce.CompareAndSwap(false, true) {
				close(dialStarted)
			}
			<-releaseDial
			return nil, errors.New("stub dial failure")
		}}
		return cs
	}()

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
	session := newTestCoreSession(msess.CoreSession{
			Options: ClientOptions{
			Server:         "masque.local",
			ServerPort:     443,
			TemplateTCP:    "https://masque.local/masque/tcp/{target_host}/{target_port}",
			TCPMode:        option.MasqueTCPModeMasqueOrDirect,
			FallbackPolicy: option.MasqueFallbackPolicyDirectExplicit,
		},
			Caps: CapabilitySet{ConnectTCP: true},
			TCPRoundTripper: roundTripperFunc(func(req *http.Request) (*http.Response, error) {
			return nil, errors.New("stub masque connect_stream unavailable")
		}),
		})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := session.DialContext(ctx, "tcp", dest)
	if err != nil {
		t.Fatalf("DialContext: %v", err)
	}
	defer conn.Close()
	select {
	case <-accepted:
	case <-time.After(time.Second):
		t.Fatal("expected direct TCP accept after MASQUE failure")
	}
}

func TestDialContextMasqueOrDirectDoesNotFallbackOnAuth(t *testing.T) {
	dest := M.ParseSocksaddrHostPort("127.0.0.1", 9)
	session := newTestCoreSession(msess.CoreSession{
			Options: ClientOptions{
			Server:         "masque.local",
			ServerPort:     443,
			TemplateTCP:    "https://masque.local/masque/tcp/{target_host}/{target_port}",
			TCPMode:        option.MasqueTCPModeMasqueOrDirect,
			FallbackPolicy: option.MasqueFallbackPolicyDirectExplicit,
		},
			Caps: CapabilitySet{ConnectTCP: true},
			TCPRoundTripper: roundTripperFunc(func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusForbidden,
				Body:       io.NopCloser(bytes.NewReader(nil)),
			}, nil
		}),
		})
	_, err := session.DialContext(context.Background(), "tcp", dest)
	if !errors.Is(err, msess.ErrAuthFailed) {
		t.Fatalf("expected msess.ErrAuthFailed without direct fallback, got: %v", err)
	}
}

func TestDialContextStrictMasqueDoesNotFallbackToDirect(t *testing.T) {
	dest := M.ParseSocksaddrHostPort("127.0.0.1", 9)
	session := newTestCoreSession(msess.CoreSession{
			Options: ClientOptions{
			Server:         "masque.local",
			ServerPort:     443,
			TemplateTCP:    "https://masque.local/masque/tcp/{target_host}/{target_port}",
			TCPMode:        option.MasqueTCPModeStrictMasque,
			FallbackPolicy: option.MasqueFallbackPolicyStrict,
		},
			Caps: CapabilitySet{ConnectTCP: true},
			TCPRoundTripper: roundTripperFunc(func(req *http.Request) (*http.Response, error) {
			return nil, errors.New("stub masque connect_stream unavailable")
		}),
		})
	_, err := session.DialContext(context.Background(), "tcp", dest)
	if !errors.Is(err, msess.ErrTCPConnectStreamFailed) {
		t.Fatalf("expected msess.ErrTCPConnectStreamFailed, got: %v", err)
	}
}

func TestDialTCPStreamAuthAndPolicyStatusesMapToAuthClass(t *testing.T) {
	for _, statusCode := range []int{http.StatusUnauthorized, http.StatusForbidden} {
		t.Run(http.StatusText(statusCode), func(t *testing.T) {
			session := newTestCoreSession(msess.CoreSession{
			Options: ClientOptions{
					Server:      "masque.local",
					ServerPort:  443,
					TemplateTCP: "https://masque.local/masque/tcp/{target_host}/{target_port}",
				},
			TCPRoundTripper: roundTripperFunc(func(req *http.Request) (*http.Response, error) {
					if req.Method != http.MethodConnect {
						t.Fatalf("unexpected method: %s", req.Method)
					}
					return &http.Response{
						StatusCode: statusCode,
						Body:       io.NopCloser(bytes.NewReader(nil)),
					}, nil
				}),
		})
			_, err := session.dialTCPStream(context.Background(), M.ParseSocksaddrHostPort("example.com", 443))
			if !errors.Is(err, msess.ErrAuthFailed) {
				t.Fatalf("expected msess.ErrAuthFailed for status=%d, got: %v", statusCode, err)
			}
			if got := msess.ClassifyError(err); got != msess.ErrorClassAuth {
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
			session := newTestCoreSession(msess.CoreSession{
			Options: ClientOptions{
					Server:      "masque.local",
					ServerPort:  443,
					TemplateTCP: "https://masque.local/masque/tcp/{target_host}/{target_port}",
				},
			TCPRoundTripper: roundTripperFunc(func(req *http.Request) (*http.Response, error) {
					return &http.Response{
						StatusCode: statusCode,
						Body:       io.NopCloser(bytes.NewReader(nil)),
					}, nil
				}),
		})
			_, err := session.dialTCPStream(context.Background(), M.ParseSocksaddrHostPort("example.com", 443))
			if !errors.Is(err, msess.ErrTCPConnectStreamFailed) {
				t.Fatalf("expected msess.ErrTCPConnectStreamFailed for non-auth non-2xx status=%d, got: %v", statusCode, err)
			}
			if got := msess.ClassifyError(err); got != msess.ErrorClassDial {
				t.Fatalf("expected dial class for non-auth non-2xx status=%d, got: %s", statusCode, got)
			}
		})
	}
}

func TestDialTCPStreamRetryableRoundTripErrorsKeepDialClassAndBudget(t *testing.T) {
	retryableErrors := map[string]error{
		"timeout_while_connecting":   timeoutNetError{msg: "timeout while connecting"},
		"no_recent_network_activity": &quic.IdleTimeoutError{},
		"idle_timeout_reached":       timeoutNetError{msg: "idle timeout reached"},
		"application_error_0x100":    &quic.ApplicationError{ErrorCode: 0x100, Remote: true},
	}
	for name, retryErr := range retryableErrors {
		t.Run(name, func(t *testing.T) {
			attempts := 0
			session := newTestCoreSession(msess.CoreSession{
			Options: ClientOptions{
					Server:      "masque.local",
					ServerPort:  443,
					TemplateTCP: "https://masque.local/masque/tcp/{target_host}/{target_port}",
				},
			TCPRoundTripper: roundTripperFunc(func(req *http.Request) (*http.Response, error) {
					attempts++
					return nil, retryErr
				}),
		})
			_, err := session.dialTCPStream(context.Background(), M.ParseSocksaddrHostPort("example.com", 443))
			if !errors.Is(err, msess.ErrTCPConnectStreamFailed) {
				t.Fatalf("expected msess.ErrTCPConnectStreamFailed, got: %v", err)
			}
			if got := msess.ClassifyError(err); got != msess.ErrorClassDial {
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
	session := newTestCoreSession(msess.CoreSession{
			Options: ClientOptions{
			Server:      "masque.local",
			ServerPort:  443,
			TemplateTCP: "https://masque.local/masque/tcp/{target_host}/{target_port}",
		},
			TCPRoundTripper: roundTripperFunc(func(req *http.Request) (*http.Response, error) {
			attempts++
			return nil, retryErr
		}),
		})
	_, err := session.dialTCPStream(context.Background(), M.ParseSocksaddrHostPort("example.com", 443))
	if !errors.Is(err, msess.ErrTCPConnectStreamFailed) {
		t.Fatalf("expected msess.ErrTCPConnectStreamFailed, got: %v", err)
	}
	if !errors.Is(err, retryErr) {
		t.Fatalf("expected retry-exhausted error to preserve the last roundtrip cause, got: %v", err)
	}
	if got := msess.ClassifyError(err); got != msess.ErrorClassDial {
		t.Fatalf("expected dial class for retry-exhausted roundtrip error, got: %s", got)
	}
	if attempts != 3 {
		t.Fatalf("expected deterministic retry budget attempts=3, got: %d", attempts)
	}
}

func TestDialTCPStreamNonRetryableRoundTripErrorDoesNotRetryAndKeepsDialClass(t *testing.T) {
	attempts := 0
	nonRetryableErr := errors.New("tls: bad certificate")
	session := newTestCoreSession(msess.CoreSession{
			Options: ClientOptions{
			Server:      "masque.local",
			ServerPort:  443,
			TemplateTCP: "https://masque.local/masque/tcp/{target_host}/{target_port}",
		},
			TCPRoundTripper: roundTripperFunc(func(req *http.Request) (*http.Response, error) {
			attempts++
			return nil, nonRetryableErr
		}),
		})
	_, err := session.dialTCPStream(context.Background(), M.ParseSocksaddrHostPort("example.com", 443))
	if !errors.Is(err, msess.ErrTCPConnectStreamFailed) {
		t.Fatalf("expected msess.ErrTCPConnectStreamFailed, got: %v", err)
	}
	if !errors.Is(err, nonRetryableErr) {
		t.Fatalf("expected non-retryable roundtrip error to preserve cause, got: %v", err)
	}
	if got := msess.ClassifyError(err); got != msess.ErrorClassDial {
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
	session := newTestCoreSession(msess.CoreSession{
			Options: ClientOptions{
			Server:      "masque.local",
			ServerPort:  443,
			TemplateTCP: "https://masque.local/masque/tcp/{target_host}/{target_port}",
		},
			TCPRoundTripper: roundTripperFunc(func(req *http.Request) (*http.Response, error) {
			attempts++
			if attempts == 1 {
				firstAttempt <- struct{}{}
			}
			return nil, timeoutNetError{msg: "timeout while connecting"}
		}),
		})
	_, err := session.dialTCPStream(ctx, M.ParseSocksaddrHostPort("example.com", 443))
	if !errors.Is(err, msess.ErrTCPConnectStreamFailed) {
		t.Fatalf("expected msess.ErrTCPConnectStreamFailed, got: %v", err)
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context cancellation cause to be preserved, got: %v", err)
	}
	if got := msess.ClassifyError(err); got != msess.ErrorClassDial {
		t.Fatalf("expected dial class when retry loop is cancelled during backoff, got: %s", got)
	}
	if attempts != 1 {
		t.Fatalf("expected cancellation during backoff to stop retries (attempts=1), got: %d", attempts)
	}
}

func TestDialTCPStreamPreAdvanceHopJoinsCauseWhenCanceledAtChainEnd(t *testing.T) {
	handshakeErr := errors.New("handshake before hop advance cancel")
	ctx, cancel := context.WithCancel(context.Background())
	session := func() *coreSession {
		s := newTestCoreSession(msess.CoreSession{
			Options: ClientOptions{
			Server:      "masque.local",
			ServerPort:  443,
			TemplateTCP: "https://masque.local/masque/tcp/{target_host}/{target_port}",
		},
			TCPRoundTripper: roundTripperFunc(func(*http.Request) (*http.Response, error) {
			return nil, handshakeErr
		}),
		})
		cs := &coreSession{CoreSession: s.CoreSession, 	dialTCPStreamPreAdvanceHopHook: func() { cancel() }}
		return cs
	}()
	session.UDPHTTPLayer.Store(option.MasqueHTTPLayerH3)
	_, err := session.dialTCPStream(ctx, M.ParseSocksaddrHostPort("example.com", 443))
	if !errors.Is(err, msess.ErrTCPConnectStreamFailed) || !errors.Is(err, context.Canceled) || !errors.Is(err, handshakeErr) {
		t.Fatalf("expected joined handshake+cancel, got: %v", err)
	}
}

func TestListenPacketUDPChainEndJoinsCauseWhenCanceledAtHopExhaustion(t *testing.T) {
	dialUDPfail := errors.New("synthetic udp dial fail")
	templateUDP, err := uritemplate.New("https://example.com/masque/udp/{target_host}/{target_port}")
	if err != nil {
		t.Fatalf("build udp template: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	s := func() *coreSession {
		s := newTestCoreSession(msess.CoreSession{
			Options: ClientOptions{
		},
			UDPClient: &qmasque.Client{},
			TemplateUDP: templateUDP,
			Caps: CapabilitySet{ConnectUDP: true},
		})
		cs := &coreSession{CoreSession: s.CoreSession, 	udpDial: func(context.Context, *qmasque.Client, *uritemplate.Template, string) (net.PacketConn, error) {
			return nil, dialUDPfail
		}, 	listenPacketPreChainEndReturnHook: func() { cancel() }}
		return cs
	}()
	_, listenErr := s.ListenPacket(ctx, M.ParseSocksaddrHostPort("127.0.0.1", 53))
	if listenErr == nil || !errors.Is(listenErr, context.Canceled) || !errors.Is(listenErr, dialUDPfail) {
		t.Fatalf("expected joined dial error+cancel at chain end, got: %v", listenErr)
	}
}

func TestDialTCPStreamOuterLoopJoinsContextCauseWhenCanceledDuringRoundTrip(t *testing.T) {
	handshakeErr := errors.New("synthetic handshake after concurrent cancel")
	entered := make(chan struct{})
	resume := make(chan struct{})
	ctx, cancel := context.WithCancel(context.Background())
	session := newTestCoreSession(msess.CoreSession{
			Options: ClientOptions{
			Server:      "masque.local",
			ServerPort:  443,
			TemplateTCP: "https://masque.local/masque/tcp/{target_host}/{target_port}",
		},
			TCPRoundTripper: roundTripperFunc(func(*http.Request) (*http.Response, error) {
			close(entered)
			<-resume
			return nil, handshakeErr
		}),
		})
	session.UDPHTTPLayer.Store(option.MasqueHTTPLayerH3)
	go func() {
		<-entered
		cancel()
		close(resume)
	}()
	_, err := session.dialTCPStream(ctx, M.ParseSocksaddrHostPort("example.com", 443))
	if !errors.Is(err, msess.ErrTCPConnectStreamFailed) {
		t.Fatalf("expected msess.ErrTCPConnectStreamFailed in chain, got: %v", err)
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled in chain (outer-loop join), got: %v", err)
	}
	if !errors.Is(err, handshakeErr) {
		t.Fatalf("expected underlying handshake error preserved, got: %v", err)
	}
}

func TestDialTCPStreamContextCanceledBeforeFirstRoundTripStopsWithoutAttempt(t *testing.T) {
	attempts := 0
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	session := newTestCoreSession(msess.CoreSession{
			Options: ClientOptions{
			Server:      "masque.local",
			ServerPort:  443,
			TemplateTCP: "https://masque.local/masque/tcp/{target_host}/{target_port}",
		},
			TCPRoundTripper: roundTripperFunc(func(req *http.Request) (*http.Response, error) {
			attempts++
			return nil, timeoutNetError{msg: "timeout while connecting"}
		}),
		})
	_, err := session.dialTCPStream(ctx, M.ParseSocksaddrHostPort("example.com", 443))
	if !errors.Is(err, msess.ErrTCPConnectStreamFailed) {
		t.Fatalf("expected msess.ErrTCPConnectStreamFailed, got: %v", err)
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context cancellation cause to be preserved, got: %v", err)
	}
	if got := msess.ClassifyError(err); got != msess.ErrorClassDial {
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
	session := newTestCoreSession(msess.CoreSession{
			Options: ClientOptions{
			Server:      "masque.local",
			ServerPort:  443,
			TemplateTCP: "https://masque.local/masque/tcp/{target_host}/{target_port}",
		},
			TCPRoundTripper: roundTripperFunc(func(req *http.Request) (*http.Response, error) {
			attempts++
			return nil, timeoutNetError{msg: "timeout while connecting"}
		}),
		})
	_, err := session.dialTCPStream(ctx, M.ParseSocksaddrHostPort("example.com", 443))
	if !errors.Is(err, msess.ErrTCPConnectStreamFailed) {
		t.Fatalf("expected msess.ErrTCPConnectStreamFailed, got: %v", err)
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected deadline exceeded cause to be preserved, got: %v", err)
	}
	if got := msess.ClassifyError(err); got != msess.ErrorClassDial {
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
	session := newTestCoreSession(msess.CoreSession{
			Options: ClientOptions{
			Server:      "masque.local",
			ServerPort:  443,
			TemplateTCP: "https://masque.local/masque/tcp/{target_host}/{target_port}",
		},
			TCPRoundTripper: roundTripperFunc(func(req *http.Request) (*http.Response, error) {
			attempts++
			return nil, timeoutNetError{msg: "timeout while connecting"}
		}),
		})
	_, err := session.dialTCPStream(ctx, M.ParseSocksaddrHostPort("example.com", 443))
	if !errors.Is(err, msess.ErrTCPConnectStreamFailed) {
		t.Fatalf("expected msess.ErrTCPConnectStreamFailed, got: %v", err)
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected deadline exceeded cause to be preserved, got: %v", err)
	}
	if got := msess.ClassifyError(err); got != msess.ErrorClassDial {
		t.Fatalf("expected dial class when retry loop is stopped by deadline during backoff, got: %s", got)
	}
	if attempts != 1 {
		t.Fatalf("expected deadline during backoff to stop retries after first attempt (attempts=1), got: %d", attempts)
	}
}

func TestDialTCPStreamContextCanceledRoundTripPreservesCauseWithoutRetry(t *testing.T) {
	attempts := 0
	session := newTestCoreSession(msess.CoreSession{
			Options: ClientOptions{
			Server:      "masque.local",
			ServerPort:  443,
			TemplateTCP: "https://masque.local/masque/tcp/{target_host}/{target_port}",
		},
			TCPRoundTripper: roundTripperFunc(func(req *http.Request) (*http.Response, error) {
			attempts++
			return nil, context.Canceled
		}),
		})
	_, err := session.dialTCPStream(context.Background(), M.ParseSocksaddrHostPort("example.com", 443))
	if !errors.Is(err, msess.ErrTCPConnectStreamFailed) {
		t.Fatalf("expected msess.ErrTCPConnectStreamFailed, got: %v", err)
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context cancellation cause to be preserved, got: %v", err)
	}
	if got := msess.ClassifyError(err); got != msess.ErrorClassDial {
		t.Fatalf("expected dial class for roundtrip context cancellation, got: %s", got)
	}
	if attempts != 1 {
		t.Fatalf("expected no retries for roundtrip context cancellation, got attempts=%d", attempts)
	}
}

func TestDialTCPStreamContextDeadlineExceededRoundTripPreservesCauseWithoutRetry(t *testing.T) {
	attempts := 0
	session := newTestCoreSession(msess.CoreSession{
			Options: ClientOptions{
			Server:      "masque.local",
			ServerPort:  443,
			TemplateTCP: "https://masque.local/masque/tcp/{target_host}/{target_port}",
		},
			TCPRoundTripper: roundTripperFunc(func(req *http.Request) (*http.Response, error) {
			attempts++
			return nil, context.DeadlineExceeded
		}),
		})
	_, err := session.dialTCPStream(context.Background(), M.ParseSocksaddrHostPort("example.com", 443))
	if !errors.Is(err, msess.ErrTCPConnectStreamFailed) {
		t.Fatalf("expected msess.ErrTCPConnectStreamFailed, got: %v", err)
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected context deadline cause to be preserved, got: %v", err)
	}
	if got := msess.ClassifyError(err); got != msess.ErrorClassDial {
		t.Fatalf("expected dial class for roundtrip deadline, got: %s", got)
	}
	if attempts != 1 {
		t.Fatalf("expected no retries for roundtrip deadline, got attempts=%d", attempts)
	}
}

func TestDialTCPStreamRelayPhaseDeadlineExceededMapsToDialClass(t *testing.T) {
	session := newTestCoreSession(msess.CoreSession{
			Options: ClientOptions{
			Server:                   "masque.local",
			ServerPort:               443,
			TemplateTCP:              "https://masque.local/masque/tcp/{target_host}/{target_port}",
			MasqueEffectiveHTTPLayer: option.MasqueHTTPLayerH2,
			TCPDial: func(context.Context, string, string) (net.Conn, error) {
				return nil, errors.New("unexpected tcp dial")
			},
		},
			TCPRoundTripper: roundTripperFunc(func(req *http.Request) (*http.Response, error) {
			startH2ConnectUploadBootstrapDrain(req)
			// dialTCPStream attaches Request.Context via connectip.NewH2ExtendedConnectRequestContext:
			// it deliberately does not inherit dial deadline cancellation on the CONNECT stream body.
			// Simulate relay-phase timeout with an independent timer on the response body.
			relayCtx, _ := context.WithTimeout(context.Background(), 40*time.Millisecond)
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       &contextBoundReadCloser{ctx: relayCtx},
			}, nil
		}),
		})
	session.UDPHTTPLayer.Store(option.MasqueHTTPLayerH2)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := session.dialTCPStream(ctx, M.ParseSocksaddrHostPort("example.com", 443))
	if err != nil {
		t.Fatalf("dial should succeed before relay-phase deadline, got: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	time.Sleep(25 * time.Millisecond)
	buf := make([]byte, 8)
	_, err = conn.Read(buf)
	if !errors.Is(err, msess.ErrTCPConnectStreamFailed) {
		t.Fatalf("expected relay-phase read error to preserve msess.ErrTCPConnectStreamFailed, got: %v", err)
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected relay-phase read error to preserve context deadline cause, got: %v", err)
	}
	if got := msess.ClassifyError(err); got != msess.ErrorClassDial {
		t.Fatalf("expected relay-phase deadline to classify as dial, got: %s", got)
	}
}

func TestDialTCPStreamRelayPhaseCanceledMapsToDialClass(t *testing.T) {
	relayCtx, relayCancel := context.WithCancel(context.Background())
	session := newTestCoreSession(msess.CoreSession{
			Options: ClientOptions{
			Server:                   "masque.local",
			ServerPort:               443,
			TemplateTCP:              "https://masque.local/masque/tcp/{target_host}/{target_port}",
			MasqueEffectiveHTTPLayer: option.MasqueHTTPLayerH2,
			TCPDial: func(context.Context, string, string) (net.Conn, error) {
				return nil, errors.New("unexpected tcp dial")
			},
		},
			TCPRoundTripper: roundTripperFunc(func(req *http.Request) (*http.Response, error) {
			startH2ConnectUploadBootstrapDrain(req)
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       &contextBoundReadCloser{ctx: relayCtx},
			}, nil
		}),
		})
	session.UDPHTTPLayer.Store(option.MasqueHTTPLayerH2)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := session.dialTCPStream(ctx, M.ParseSocksaddrHostPort("example.com", 443))
	if err != nil {
		t.Fatalf("dial should succeed before relay-phase cancel, got: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	relayCancel()

	buf := make([]byte, 8)
	_, err = conn.Read(buf)
	if !errors.Is(err, msess.ErrTCPConnectStreamFailed) {
		t.Fatalf("expected relay-phase read error to preserve msess.ErrTCPConnectStreamFailed, got: %v", err)
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected relay-phase read error to preserve context cancel cause, got: %v", err)
	}
	if got := msess.ClassifyError(err); got != msess.ErrorClassDial {
		t.Fatalf("expected relay-phase cancel to classify as dial, got: %s", got)
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
	waitCtx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	session, err := (CoreClientFactory{}).NewSession(waitCtx, ClientOptions{
		Server:       "127.0.0.1",
		ServerPort:   uint16(proxyPort),
		MasqueQUICCryptoTLS: &tls.Config{InsecureSkipVerify: true},
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
			waitCtx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
			defer cancel()
			session, err := (CoreClientFactory{}).NewSession(waitCtx, ClientOptions{
				Server:       "127.0.0.1",
				ServerPort:   uint16(proxyPort),
				MasqueQUICCryptoTLS: &tls.Config{InsecureSkipVerify: true},
			})
			if err != nil {
				t.Fatalf("new session: %v", err)
			}
			t.Cleanup(func() { _ = session.Close() })

			_, err = session.DialContext(waitCtx, "tcp", M.ParseSocksaddrHostPort("127.0.0.1", 443))
			if !errors.Is(err, msess.ErrAuthFailed) {
				t.Fatalf("expected msess.ErrAuthFailed for status=%d, got: %v", statusCode, err)
			}
			if got := msess.ClassifyError(err); got != msess.ErrorClassAuth {
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
			waitCtx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
			defer cancel()
			session, err := (CoreClientFactory{}).NewSession(waitCtx, ClientOptions{
				Server:       "127.0.0.1",
				ServerPort:   uint16(proxyPort),
				MasqueQUICCryptoTLS: &tls.Config{InsecureSkipVerify: true},
			})
			if err != nil {
				t.Fatalf("new session: %v", err)
			}
			t.Cleanup(func() { _ = session.Close() })

			_, err = session.DialContext(waitCtx, "tcp", M.ParseSocksaddrHostPort("127.0.0.1", 443))
			if !errors.Is(err, msess.ErrTCPConnectStreamFailed) {
				t.Fatalf("expected msess.ErrTCPConnectStreamFailed for non-auth status=%d, got: %v", statusCode, err)
			}
			if got := msess.ClassifyError(err); got != msess.ErrorClassDial {
				t.Fatalf("expected dial class for non-auth status=%d, got: %s", statusCode, got)
			}
		})
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
	waitCtx, waitCancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer waitCancel()
	var attempts int32
	retryableErr := timeoutNetError{msg: "timeout during quic dial"}
	session, err := (CoreClientFactory{}).NewSession(waitCtx, ClientOptions{
		Server:       "127.0.0.1",
		ServerPort:   uint16(proxyPort),
		MasqueQUICCryptoTLS: &tls.Config{InsecureSkipVerify: true},
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
	waitCtx, waitCancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer waitCancel()
	var attempts int32
	retryableErr := &quic.ApplicationError{ErrorCode: 0x100, Remote: true}
	session, err := (CoreClientFactory{}).NewSession(waitCtx, ClientOptions{
		Server:       "127.0.0.1",
		ServerPort:   uint16(proxyPort),
		MasqueQUICCryptoTLS: &tls.Config{InsecureSkipVerify: true},
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

type tierBPacketConnStub struct{}

func (s *tierBPacketConnStub) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	return 0, &net.UDPAddr{}, io.EOF
}
func (s *tierBPacketConnStub) WriteTo(p []byte, addr net.Addr) (n int, err error) { return len(p), nil }
func (s *tierBPacketConnStub) Close() error                                       { return nil }
func (s *tierBPacketConnStub) LocalAddr() net.Addr                                { return &net.UDPAddr{} }
func (s *tierBPacketConnStub) SetDeadline(t time.Time) error                      { return nil }
func (s *tierBPacketConnStub) SetReadDeadline(t time.Time) error                  { return nil }
func (s *tierBPacketConnStub) SetWriteDeadline(t time.Time) error                 { return nil }

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
			waitCtx, waitCancel := context.WithTimeout(context.Background(), 4*time.Second)
			defer waitCancel()
			var attempts int32
			session, err := (CoreClientFactory{}).NewSession(waitCtx, ClientOptions{
				Server:       "127.0.0.1",
				ServerPort:   uint16(proxyPort),
				MasqueQUICCryptoTLS: &tls.Config{InsecureSkipVerify: true},
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

func TestConnectIPObservabilitySnapshotIncludesHTTP3StreamDatagramQueueDrops(t *testing.T) {
	snapshot := mcip.ObservabilitySnapshot()
	raw, ok := snapshot["http3_stream_datagram_queue_drop_total"]
	if !ok {
		t.Fatal("expected http3_stream_datagram_queue_drop_total in ConnectIPObservabilitySnapshot")
	}
	if _, ok := raw.(uint64); !ok {
		t.Fatalf("unexpected type for http3_stream_datagram_queue_drop_total: %T", raw)
	}
}

func TestConnectIPObservabilitySnapshotIncludesQUICDatagramRcvQueueDrops(t *testing.T) {
	snapshot := mcip.ObservabilitySnapshot()
	raw, ok := snapshot["quic_datagram_rcv_queue_drop_total"]
	if !ok {
		t.Fatal("expected quic_datagram_rcv_queue_drop_total in ConnectIPObservabilitySnapshot")
	}
	if _, ok := raw.(uint64); !ok {
		t.Fatalf("unexpected type for quic_datagram_rcv_queue_drop_total: %T", raw)
	}
}

type recordingIPPacketSession struct {
	lastWrite  []byte
	writes     [][]byte
	readPacket []byte
	writeICMP  []byte
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
	if len(s.writeICMP) == 0 {
		return nil, nil
	}
	return append([]byte(nil), s.writeICMP...), nil
}

func (s *recordingIPPacketSession) Close() error { return nil }

func TestConnectIPUDPBridgeICMPPortUnreachableFromWrite(t *testing.T) {
	orig, err := mcip.BuildIPv4UDPPacket(
		netip.MustParseAddr("198.18.0.2"),
		53000,
		netip.MustParseAddr("10.200.0.2"),
		5601,
		[]byte("dns"),
	)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	icmpPkt := make([]byte, 20+8+len(orig))
	icmpPkt[0] = 0x45
	icmpPkt[9] = 1
	icmpPkt[20] = 3
	icmpPkt[21] = 3
	copy(icmpPkt[28:], orig)
	rec := &recordingIPPacketSession{writeICMP: icmpPkt}
	conn := newConnectIPUDPPacketConn(context.Background(), rec, nil)
	dst := &net.UDPAddr{IP: net.ParseIP("10.200.0.2"), Port: 5601}
	if _, err := conn.WriteTo([]byte("q"), dst); err != nil {
		t.Fatalf("write: %v", err)
	}
	_, _, err = conn.ReadFrom(make([]byte, 64))
	if !errors.Is(err, mcip.ErrICMPPortUnreachable) {
		t.Fatalf("read: %v want ErrICMPPortUnreachable", err)
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

// startH2ConnectUploadBootstrapDrain simulates http2.Transport consuming CONNECT upload bootstrap DATA.
func startH2ConnectUploadBootstrapDrain(req *http.Request) {
	if req == nil || req.Body == nil {
		return
	}
	go func() {
		buf := make([]byte, strm.H2BidiBootstrapUploadBytes)
		_, _ = io.ReadFull(req.Body, buf)
	}()
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
