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
	"net/url"
	"os"
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

func TestMasqueUDPExpandedURLAuthority(t *testing.T) {
	raw := "https://proxy.example:8443/masque/udp/{target_host}/{target_port}"
	tpl, err := uritemplate.New(raw)
	if err != nil {
		t.Fatal(err)
	}
	if got := masqueUDPExpandedURLAuthority(tpl, "1.2.3.4:5353"); got != "proxy.example:8443" {
		t.Fatalf("authority: got %q", got)
	}
	if masqueUDPExpandedURLAuthority(nil, "1.2.3.4:53") != "" {
		t.Fatal("nil template expected empty authority")
	}
	if masqueUDPExpandedURLAuthority(tpl, "nohostport") != "" {
		t.Fatal("bad target expected empty authority")
	}
}

func TestMasqueUDPConnectObservabilityFields(t *testing.T) {
	t.Parallel()
	raw := "https://proxy.example:8443/masque/udp/{target_host}/{target_port}"
	tpl, err := uritemplate.New(raw)
	if err != nil {
		t.Fatal(err)
	}
	opts := ClientOptions{Server: "edge.example", ServerPort: 443}
	lt, dial := masqueUDPConnectObservabilityFields(opts, tpl, "1.2.3.4:5353")
	if lt != "proxy.example:8443" {
		t.Fatalf("target: got %q", lt)
	}
	if want := masqueDialTarget(masqueQuicDialCandidateHost(opts), 443); dial != want {
		t.Fatalf("dial: got %q want %q", dial, want)
	}
	optsZero := ClientOptions{Server: "srv.example", ServerPort: 0}
	if _, d0 := masqueUDPConnectObservabilityFields(optsZero, tpl, "8.8.8.8:53"); d0 != masqueDialTarget(masqueQuicDialCandidateHost(optsZero), 443) {
		t.Fatalf("implicit 443 dial mismatch")
	}
}

func TestMasqueConnectIPOverlayDialAddr(t *testing.T) {
	t.Parallel()
	opts := ClientOptions{Server: "ip.example", ServerPort: 444}
	if got := masqueConnectIPOverlayDialAddr(opts); got != masqueDialTarget(masqueQuicDialCandidateHost(opts), 444) {
		t.Fatalf("got %q", got)
	}
	optsZero := ClientOptions{Server: "z.example", ServerPort: 0}
	if got := masqueConnectIPOverlayDialAddr(optsZero); got != masqueDialTarget(masqueQuicDialCandidateHost(optsZero), 443) {
		t.Fatalf("implicit port: got %q", got)
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
	if got := resolveTLSServerName(ClientOptions{TLSServerName: "  sni.example  ", Server: "  ignored.example "}); got != "sni.example" {
		t.Fatalf("explicit SNI: got %q", got)
	}
	if got := resolveTLSServerName(ClientOptions{Server: "  host.example "}); got != "host.example" {
		t.Fatalf("fallback Server: got %q", got)
	}
	if got := resolveTLSServerName(ClientOptions{TLSServerName: "\t ", Server: "edge.example"}); got != "edge.example" {
		t.Fatalf("whitespace-only SNI falls back to Server: got %q", got)
	}
}

func TestWarpMasqueConnectStreamBearerToken(t *testing.T) {
	if got := warpMasqueConnectStreamBearerToken(ClientOptions{ServerToken: "  s  "}); got != "s" {
		t.Fatalf("server token trim: got %q", got)
	}
	if got := warpMasqueConnectStreamBearerToken(ClientOptions{WarpMasqueDeviceBearerToken: " d "}); got != "d" {
		t.Fatalf("device bearer fallback: got %q", got)
	}
	if got := warpMasqueConnectStreamBearerToken(ClientOptions{ServerToken: "a", WarpMasqueDeviceBearerToken: "b"}); got != "a" {
		t.Fatalf("prefer server_token: got %q", got)
	}
	warpCert := tls.Certificate{Certificate: [][]byte{[]byte{0x30, 0x03, 0x01, 0x02, 0x03}}}
	if got := warpMasqueConnectStreamBearerToken(ClientOptions{
		WarpMasqueClientCert:        warpCert,
		WarpMasqueDeviceBearerToken: "device-token",
	}); got != "" {
		t.Fatalf("WARP mTLS must omit device bearer on connect-stream; got %q", got)
	}
	if got := warpMasqueConnectStreamBearerToken(ClientOptions{
		WarpMasqueClientCert:        warpCert,
		ServerToken:                 "srv",
		WarpMasqueDeviceBearerToken: "device",
	}); got != "srv" {
		t.Fatalf("server_token must win with WARP cert; got %q", got)
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
	// CONNECT-IP (openIPSessionLocked) and ListenPacket/connect_ip dial while holding s.mu.
	// getTCPRoundTripper must not acquire s.mu or the session deadlocks before the network round-trip.
	naked := &coreSession{}
	naked.mu.Lock()
	rt := naked.getTCPRoundTripper(http.DefaultTransport)
	naked.mu.Unlock()
	if rt != http.DefaultTransport {
		t.Fatalf("expected DefaultTransport without override, got %T", rt)
	}
	injected := &coreSession{
		tcpRoundTripper: roundTripperFunc(func(*http.Request) (*http.Response, error) {
			return nil, errors.New("stub")
		}),
	}
	injected.mu.Lock()
	rt = injected.getTCPRoundTripper(http.DefaultTransport)
	injected.mu.Unlock()
	if rt == http.DefaultTransport {
		t.Fatal("expected injected RoundTripper when tcpRoundTripper is set")
	}
}

func TestDialTCPStreamAdvancesHopChainAfterRetries(t *testing.T) {
	var mu sync.Mutex
	var dialHosts []string
	session := &coreSession{
		options: ClientOptions{
			Server:                   "hop1.example",
			ServerPort:               443,
			TCPTransport:             "connect_stream",
			MasqueEffectiveHTTPLayer: option.MasqueHTTPLayerH3,
		},
		hopOrder: []HopOptions{
			{Tag: "hop1", Server: "hop1.example", Port: 443},
			{Tag: "hop2", Via: "hop1", Server: "hop2.example", Port: 8443},
		},
		hopIndex:          0,
		capabilities:      CapabilitySet{ConnectTCP: true},
		httpLayerFallback: false,
		tcpRoundTripper: roundTripperFunc(func(req *http.Request) (*http.Response, error) {
			mu.Lock()
			dialHosts = append(dialHosts, req.Host)
			mu.Unlock()
			// Must be retryable for dialTCPStreamHTTP3 inner loop (same as UDP hop logic after datagram failures).
			return nil, timeoutNetError{msg: "timeout while connecting"}
		}),
	}
	session.udpHTTPLayer.Store(option.MasqueHTTPLayerH3)
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
	session.templateTCP = tcp
	_, err = session.dialTCPStream(context.Background(), M.ParseSocksaddrHostPort("example.com", 443))
	if err == nil {
		t.Fatal("expected error after exhausting hop chain")
	}
	mu.Lock()
	defer mu.Unlock()
	if len(dialHosts) != 6 {
		t.Fatalf("expected 3 http3 round-trip attempts per hop × 2 hops = 6, got %d (%v)", len(dialHosts), dialHosts)
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
	if session.options.Server != "hop2.example" || session.options.ServerPort != 8443 {
		t.Fatalf("expected session settled on last hop server, got %s:%d", session.options.Server, session.options.ServerPort)
	}
}

func TestDialTCPStreamDoesNotAdvanceHopOnLocalConfigError(t *testing.T) {
	session := &coreSession{
		options: ClientOptions{
			Server:                   "hop1.example",
			ServerPort:               443,
			TCPTransport:             "connect_stream",
			MasqueEffectiveHTTPLayer: option.MasqueHTTPLayerH3,
		},
		hopOrder: []HopOptions{
			{Tag: "hop1", Server: "hop1.example", Port: 443},
			{Tag: "hop2", Via: "hop1", Server: "hop2.example", Port: 8443},
		},
		hopIndex:          0,
		capabilities:      CapabilitySet{ConnectTCP: true},
		httpLayerFallback: true,
	}
	session.udpHTTPLayer.Store(option.MasqueHTTPLayerH3)
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
	session.templateTCP = tcp
	_, err = session.dialTCPStream(context.Background(), M.Socksaddr{})
	if err == nil {
		t.Fatal("expected error for invalid destination")
	}
	if !errors.Is(err, ErrCapability) {
		t.Fatalf("expected ErrCapability, got %v", err)
	}
	if session.hopIndex != 0 {
		t.Fatalf("expected hop chain untouched (invalid destination), hopIndex=%d", session.hopIndex)
	}
	if session.options.Server != "hop1.example" || session.options.ServerPort != 443 {
		t.Fatalf("expected entry hop unchanged, got %s:%d", session.options.Server, session.options.ServerPort)
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

func TestResetHopTemplatesClearsTCPNetstack(t *testing.T) {
	ns := &nopTCPNetstack{}
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
		hopIndex:    1,
		tcpNetstack: ns,
	}
	if err := session.resetHopTemplates(); err != nil {
		t.Fatalf("resetHopTemplates failed: %v", err)
	}
	if session.tcpNetstack != nil {
		t.Fatal("expected tcpNetstack cleared on hop reset")
	}
	if !ns.closeCalled.Load() {
		t.Fatal("expected TCP netstack Close on hop reset")
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

func TestResetHopTemplatesClearsSharedIPH3Refs(t *testing.T) {
	shared := &http3.Transport{}
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
		tcpHTTP:  shared,
		ipHTTP:   shared,
	}
	if err := session.resetHopTemplates(); err != nil {
		t.Fatalf("resetHopTemplates failed: %v", err)
	}
	if session.ipHTTP != nil || session.tcpHTTP != nil || session.ipHTTPConn != nil {
		t.Fatalf("expected shared ip/tcp http3.Transport cleared on hop reset, ipHTTP=%v tcpHTTP=%v ipHTTPConn=%v", session.ipHTTP, session.tcpHTTP, session.ipHTTPConn)
	}
}

func TestResetTCPHTTPTransportClearsSharedIPH3Refs(t *testing.T) {
	shared := &http3.Transport{}
	s := &coreSession{
		options: ClientOptions{
			Server:     "example.com",
			ServerPort: 443,
		},
		tcpHTTP: shared,
		ipHTTP:  shared,
	}
	s.resetTCPHTTPTransport()
	if s.tcpHTTP == nil || s.tcpHTTP == shared {
		t.Fatal("expected fresh tcpHTTP after reset")
	}
	if s.ipHTTP != nil || s.ipHTTPConn != nil {
		t.Fatal("expected shared CONNECT-IP http3.Transport pointer cleared alongside tcpHTTP rebuild")
	}
}

func TestResetHopTemplatesClearsDialPeerOnInnerHop(t *testing.T) {
	session := &coreSession{
		options: ClientOptions{
			Server:     "entry.example",
			DialPeer:   "203.0.113.77",
			ServerPort: 443,
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
	}
	if err := session.resetHopTemplates(); err != nil {
		t.Fatalf("resetHopTemplates failed: %v", err)
	}
	if session.options.Server != "next.example" || session.options.ServerPort != 8443 {
		t.Fatalf("unexpected hop templates server: got %s:%d", session.options.Server, session.options.ServerPort)
	}
	if strings.TrimSpace(session.options.DialPeer) != "" {
		t.Fatalf("expected DialPeer cleared past entry hop, got %q", session.options.DialPeer)
	}
}

func TestResetHopTemplatesPreservesHTTPOverlay(t *testing.T) {
	session := &coreSession{
		options: ClientOptions{
			Server:                   "entry.example",
			MasqueEffectiveHTTPLayer: option.MasqueHTTPLayerH3,
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
	}
	session.udpHTTPLayer.Store(option.MasqueHTTPLayerH2)
	session.httpFallbackConsumed.Store(true)

	if err := session.resetHopTemplates(); err != nil {
		t.Fatalf("resetHopTemplates failed: %v", err)
	}
	if session.currentUDPHTTPLayer() != option.MasqueHTTPLayerH2 {
		t.Fatalf("expected udp overlay h2 preserved across hop reset, got %q", session.currentUDPHTTPLayer())
	}
	if session.httpFallbackConsumed.Load() {
		t.Fatal("expected httpFallbackConsumed reset to false for the new hop")
	}
}

func TestMaybeRecordHTTPLayerCacheSuccessSkipsInnerHop(t *testing.T) {
	var calls atomic.Int32
	s := &coreSession{
		options: ClientOptions{
			Server:                   "hop2.example",
			ServerPort:               8443,
			MasqueEffectiveHTTPLayer: option.MasqueHTTPLayerAuto,
			HTTPLayerSuccess: func(layer string, id HTTPLayerCacheDialIdentity) {
				calls.Add(1)
			},
		},
		hopOrder: []HopOptions{
			{Tag: "hop1", Server: "hop1.example", Port: 443},
			{Tag: "hop2", Via: "hop1", Server: "hop2.example", Port: 8443},
		},
		hopIndex: 1,
	}
	s.maybeRecordHTTPLayerCacheSuccess(option.MasqueHTTPLayerH2)
	if calls.Load() != 0 {
		t.Fatalf("expected no cache record on inner hop, got %d calls", calls.Load())
	}
	s.hopIndex = 0
	s.maybeRecordHTTPLayerCacheSuccess(option.MasqueHTTPLayerH3)
	if calls.Load() != 1 {
		t.Fatalf("expected one cache record on entry hop, got %d", calls.Load())
	}
}

func TestDialConnectIPAttemptHookRecordsHTTPLayerCacheSuccess(t *testing.T) {
	okConn := &connectip.Conn{}
	var gotLayer atomic.Value
	s := &coreSession{
		options: ClientOptions{
			TransportMode: "connect_ip",
			Server:        "example.com",
			ServerPort:    443,
			HTTPLayerSuccess: func(layer string, id HTTPLayerCacheDialIdentity) {
				gotLayer.Store(layer)
			},
		},
		dialConnectIPAttemptHook: func(ctx context.Context, useHTTP2 bool) (*connectip.Conn, error) {
			return okConn, nil
		},
	}
	s.hopOrder = nil
	s.hopIndex = 0

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

func TestApplyWarpMasqueHTTP3TransportFieldsCfConnectIPEnablesLegacy276(t *testing.T) {
	tr := &http3.Transport{}
	applyWarpMasqueHTTP3TransportFields(tr, ClientOptions{
		WarpMasqueLegacyH3Extras: false,
		WarpConnectIPProtocol:    "cf-connect-ip",
	})
	if tr.AdditionalSettings == nil || tr.AdditionalSettings[cloudflareLegacyH3DatagramSettingID] != 1 {
		t.Fatalf("expected legacy H3 datagram setting for cf-connect-ip, got %#v", tr.AdditionalSettings)
	}
	if !tr.DisableCompression {
		t.Fatal("expected DisableCompression for WARP H3 extras path")
	}
}

func TestApplyWarpMasqueHTTP3TransportFieldsNoopWithoutExtrasOrCf(t *testing.T) {
	tr := &http3.Transport{}
	applyWarpMasqueHTTP3TransportFields(tr, ClientOptions{})
	if len(tr.AdditionalSettings) > 0 {
		t.Fatalf("unexpected AdditionalSettings: %#v", tr.AdditionalSettings)
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
	streamSession, err := (CoreClientFactory{}).NewSession(context.TODO(), ClientOptions{
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

	ipSession, err := (CoreClientFactory{}).NewSession(context.TODO(), ClientOptions{
		Server:       "example.com",
		ServerPort:   443,
		TCPTransport: "connect_ip",
	})
	if err != nil {
		t.Fatalf("new connect_ip session: %v", err)
	}
	if ipSession.Capabilities().ConnectTCP {
		t.Fatal("expected connect_ip tcp without transport_mode=connect_ip to disable ConnectTCP")
	}

	tcpOverIPSession, err := (CoreClientFactory{}).NewSession(context.TODO(), ClientOptions{
		Server:        "example.com",
		ServerPort:    443,
		TransportMode: "connect_ip",
		TCPTransport:  "connect_ip",
	})
	if err != nil {
		t.Fatalf("new tcp connect_ip session: %v", err)
	}
	if !tcpOverIPSession.Capabilities().ConnectTCP {
		t.Fatal("expected connect_ip+transport connect_ip session to advertise ConnectTCP")
	}
}

func TestCoreSessionCapabilitiesDatagramsTracksHTTPLayerOverlay(t *testing.T) {
	cs := &coreSession{
		options: ClientOptions{
			MasqueEffectiveHTTPLayer: option.MasqueHTTPLayerH2,
			Server:                   "example.com",
			ServerPort:               443,
		},
		capabilities: CapabilitySet{
			ExtendedConnect: true,
			Datagrams:       false,
			CapsuleProtocol: true,
			ConnectUDP:      true,
			ConnectIP:       true,
		},
	}
	cs.udpHTTPLayer.Store(option.MasqueHTTPLayerH2)
	if cs.Capabilities().Datagrams {
		t.Fatal("expected Datagrams=false on h2 overlay")
	}
	cs.udpHTTPLayer.Store(option.MasqueHTTPLayerH3)
	if !cs.Capabilities().Datagrams {
		t.Fatal("expected Datagrams=true on h3 overlay after rotation from h2-effective ctor")
	}

	csH3 := &coreSession{
		options: ClientOptions{
			MasqueEffectiveHTTPLayer: option.MasqueHTTPLayerH3,
			Server:                   "example.com",
			ServerPort:               443,
		},
		capabilities: CapabilitySet{
			ExtendedConnect: true,
			Datagrams:       true,
			CapsuleProtocol: true,
			ConnectUDP:      true,
			ConnectIP:       true,
		},
	}
	csH3.udpHTTPLayer.Store(option.MasqueHTTPLayerH3)
	if !csH3.Capabilities().Datagrams {
		t.Fatal("expected Datagrams=true on h3 overlay with h3-effective ctor")
	}
	csH3.udpHTTPLayer.Store(option.MasqueHTTPLayerH2)
	if csH3.Capabilities().Datagrams {
		t.Fatal("expected Datagrams=false on h2 overlay with h3-effective ctor")
	}
}

func TestDirectClientFactoryConnectTCPCapabilityByTransport(t *testing.T) {
	streamSession, err := (DirectClientFactory{}).NewSession(context.TODO(), ClientOptions{
		TCPTransport: "connect_stream",
	})
	if err != nil {
		t.Fatalf("new direct connect_stream session: %v", err)
	}
	if !streamSession.Capabilities().ConnectTCP {
		t.Fatal("expected direct connect_stream session to advertise ConnectTCP")
	}

	autoSession, err := (DirectClientFactory{}).NewSession(context.TODO(), ClientOptions{
		TCPTransport: "auto",
	})
	if err != nil {
		t.Fatalf("new direct auto session: %v", err)
	}
	if autoSession.Capabilities().ConnectTCP {
		t.Fatal("expected direct auto session to disable ConnectTCP")
	}

	ipSession, err := (DirectClientFactory{}).NewSession(context.TODO(), ClientOptions{
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

func TestDirectSessionListenPacketReturnsCanceledBeforeBind(t *testing.T) {
	session := &directSession{
		capabilities: CapabilitySet{ConnectUDP: true},
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := session.ListenPacket(ctx, M.ParseSocksaddrHostPort("127.0.0.1", 53))
	if err == nil {
		t.Fatal("expected canceled context to skip ListenPacket bind")
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Cause to surface cancel, got: %v", err)
	}
}

func TestDirectSessionDialContextReturnsCanceledBeforeHostResolve(t *testing.T) {
	session := &directSession{tcpTransport: option.MasqueTCPTransportConnectStream}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := session.DialContext(ctx, "tcp", M.ParseSocksaddrHostPort("example.com", 443))
	if err == nil {
		t.Fatal("expected canceled context before direct tcp dial work")
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Cause to surface cancel, got: %v", err)
	}
}

func TestDirectSessionOpenIPSessionReturnsCanceledBeforeCapabilityBoundary(t *testing.T) {
	session := &directSession{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := session.OpenIPSession(ctx)
	if err == nil {
		t.Fatal("expected canceled context before direct CONNECT-IP capability checks")
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Cause to surface cancel, got: %v", err)
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

func TestResolveDestinationHostTrimsPaddedFqdnFromParseSocksaddr(t *testing.T) {
	dest := M.ParseSocksaddrHostPort("  example.com\t", 443)
	host, err := resolveDestinationHost(dest)
	if err != nil {
		t.Fatalf("resolveDestinationHost: %v", err)
	}
	if host != "example.com" {
		t.Fatalf("expected trimmed fqdn example.com, got %q", host)
	}
}

func TestResolveDestinationHostPaddedFqdnDoesNotOverrideIP(t *testing.T) {
	dest := M.Socksaddr{
		Addr: netip.MustParseAddr("198.51.100.1"),
		Port: 443,
		Fqdn: "  example.com ",
	}
	host, err := resolveDestinationHost(dest)
	if err != nil {
		t.Fatalf("resolveDestinationHost: %v", err)
	}
	if host != "198.51.100.1" {
		t.Fatalf("expected IP when both addr and padded fqdn present, got %q", host)
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

func TestStreamConnReadKeepsEOFWhenDialCtxCanceled(t *testing.T) {
	dialCtx, cancel := context.WithCancel(context.Background())
	cancel()
	c := &streamConn{
		reader: io.NopCloser(strings.NewReader("")),
		writer: &fakeWriter{},
		ctx:    dialCtx,
	}
	var buf [4]byte
	n, err := c.Read(buf[:])
	if n != 0 || !errors.Is(err, io.EOF) {
		t.Fatalf("expected io.EOF, got n=%d err=%v", n, err)
	}
}

type streamConnFixedErrWriter struct{ err error }

func (w streamConnFixedErrWriter) Write(p []byte) (int, error) {
	if w.err != nil {
		return 0, w.err
	}
	return len(p), nil
}
func (streamConnFixedErrWriter) Close() error { return nil }

func TestStreamConnWriteKeepsEOFWhenDialCtxCanceled(t *testing.T) {
	dialCtx, cancel := context.WithCancel(context.Background())
	cancel()
	c := &streamConn{
		reader: io.NopCloser(strings.NewReader("")),
		writer: streamConnFixedErrWriter{err: io.EOF},
		ctx:    dialCtx,
	}
	n, err := c.Write([]byte("ping"))
	if n != 0 || !errors.Is(err, io.EOF) {
		t.Fatalf("expected io.EOF, got n=%d err=%v", n, err)
	}
}

func TestStreamConnWriteKeepsErrClosedPipeWhenDialCtxCanceledH2UploadPipe(t *testing.T) {
	dialCtx, cancel := context.WithCancel(context.Background())
	cancel()
	pr, _ := io.Pipe()
	c := &streamConn{
		reader:       io.NopCloser(strings.NewReader("")),
		writer:       streamConnFixedErrWriter{err: io.ErrClosedPipe},
		h2UploadPipe: pr,
		ctx:          dialCtx,
	}
	n, err := c.Write([]byte("ping"))
	if n != 0 || !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("expected io.ErrClosedPipe, got n=%d err=%v", n, err)
	}
	_ = pr.Close()
}

func TestStreamConnReadKeepsErrClosedPipeWhenDialCtxCanceledH2UploadPipe(t *testing.T) {
	dialCtx, cancel := context.WithCancel(context.Background())
	cancel()
	pr, _ := io.Pipe()
	c := &streamConn{
		reader:       streamConnFixedErrReader{err: io.ErrClosedPipe},
		writer:       &fakeWriter{},
		h2UploadPipe: pr,
		ctx:          dialCtx,
	}
	var buf [4]byte
	n, err := c.Read(buf[:])
	if n != 0 || !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("expected io.ErrClosedPipe, got n=%d err=%v", n, err)
	}
	_ = pr.Close()
}

func TestStreamConnReadWriteMapsOsDeadlineExceededToDialClass(t *testing.T) {
	c := &streamConn{
		reader: io.NopCloser(streamConnFixedErrReader{err: os.ErrDeadlineExceeded}),
		writer: streamConnFixedErrWriter{err: os.ErrDeadlineExceeded},
		ctx:    context.Background(),
	}
	var buf [4]byte
	_, err := c.Read(buf[:])
	if !errors.Is(err, ErrTCPConnectStreamFailed) || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("read: want ErrTCPConnectStreamFailed+DeadlineExceeded, got %v", err)
	}
	if got := ClassifyError(err); got != ErrorClassDial {
		t.Fatalf("read classify: want %s got %s", ErrorClassDial, got)
	}

	_, err = c.Write([]byte{1})
	if !errors.Is(err, ErrTCPConnectStreamFailed) || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("write: want ErrTCPConnectStreamFailed+DeadlineExceeded, got %v", err)
	}
	if got := ClassifyError(err); got != ErrorClassDial {
		t.Fatalf("write classify: want %s got %s", ErrorClassDial, got)
	}
}

func TestStreamConnWriteBlamesDialCtxWhenCanceledOnPeerError(t *testing.T) {
	dialCtx, cancel := context.WithCancel(context.Background())
	cancel()
	want := errors.New("peer reset")
	c := &streamConn{
		reader: io.NopCloser(strings.NewReader("")),
		writer: streamConnFixedErrWriter{err: want},
		ctx:    dialCtx,
	}
	_, err := c.Write([]byte("ping"))
	if !errors.Is(err, ErrTCPConnectStreamFailed) || !errors.Is(err, context.Canceled) {
		t.Fatalf("expected join with dial cancel, got err=%v", err)
	}
}

func TestStreamConnWritePassesPeerErrorThroughWhenCtxDetachedFromDialCancel(t *testing.T) {
	dialCtx, cancel := context.WithCancel(context.Background())
	cancel()
	want := errors.New("peer reset")
	c := &streamConn{
		reader: io.NopCloser(strings.NewReader("")),
		writer: streamConnFixedErrWriter{err: want},
		ctx:    context.WithoutCancel(dialCtx),
	}
	_, err := c.Write([]byte("ping"))
	if errors.Is(err, ErrTCPConnectStreamFailed) || errors.Is(err, context.Canceled) {
		t.Fatalf("expected no dial-error join when ctx detached, got err=%v", err)
	}
	if err == nil || !strings.Contains(err.Error(), "masque h3 dataplane connect-stream write") || !errors.Is(err, want) {
		t.Fatalf("expected H3 dataplane wrapper with unwrap to peer cause, got err=%v", err)
	}
}

type streamConnFixedErrReader struct{ err error }

func (r streamConnFixedErrReader) Read(p []byte) (int, error) { return 0, r.err }
func (r streamConnFixedErrReader) Close() error               { return nil }

func TestStreamConnReadBlamesDialCtxWhenCanceledOnPeerError(t *testing.T) {
	dialCtx, cancel := context.WithCancel(context.Background())
	cancel()
	want := errors.New("peer reset")
	c := &streamConn{
		reader: streamConnFixedErrReader{err: want},
		writer: &fakeWriter{},
		ctx:    dialCtx,
	}
	var buf [4]byte
	_, err := c.Read(buf[:])
	if !errors.Is(err, ErrTCPConnectStreamFailed) || !errors.Is(err, context.Canceled) {
		t.Fatalf("expected join with dial cancel, got err=%v", err)
	}
}

func TestStreamConnReadPassesPeerErrorThroughWhenCtxDetachedFromDialCancel(t *testing.T) {
	dialCtx, cancel := context.WithCancel(context.Background())
	cancel()
	want := errors.New("peer reset")
	c := &streamConn{
		reader: streamConnFixedErrReader{err: want},
		writer: &fakeWriter{},
		ctx:    context.WithoutCancel(dialCtx),
	}
	var buf [4]byte
	_, err := c.Read(buf[:])
	if errors.Is(err, ErrTCPConnectStreamFailed) || errors.Is(err, context.Canceled) {
		t.Fatalf("expected no dial-error join when ctx detached, got err=%v", err)
	}
	if err == nil || !strings.Contains(err.Error(), "masque h3 dataplane connect-stream read") || !errors.Is(err, want) {
		t.Fatalf("expected H3 dataplane wrapper with unwrap to peer cause, got err=%v", err)
	}
}

func TestStreamConnH3DataplaneWrapsReadWriteErrors(t *testing.T) {
	rootHTTP2 := errors.New(`stream read: QUIC layer reported handshake timeout (nested)`)
	rootBrokenPipe := errors.New("write tcp: broken pipe")

	rConn := &streamConn{
		reader: io.NopCloser(streamConnFixedErrReader{err: rootHTTP2}),
		writer: &fakeWriter{},
		ctx:    context.Background(),
	}
	var buf [4]byte
	if _, err := rConn.Read(buf[:]); err == nil || !strings.Contains(err.Error(), "masque h3 dataplane connect-stream read") || !errors.Is(err, rootHTTP2) {
		t.Fatalf("expected H3 dataplane-wrapped read with unwrap chain; got %v", err)
	}

	wConn := &streamConn{
		reader: io.NopCloser(streamConnFixedErrReader{errors.New("unused")}),
		writer: errorPipeWriter{err: rootBrokenPipe},
		ctx:    context.Background(),
	}
	if _, err := wConn.Write([]byte("x")); err == nil || !strings.Contains(err.Error(), "masque h3 dataplane connect-stream write") || !errors.Is(err, rootBrokenPipe) {
		t.Fatalf("expected H3 dataplane-wrapped write with unwrap chain; got %v", err)
	}
}

func TestStreamConnH2DataplaneWrapsReadWriteErrors(t *testing.T) {
	prR, pwR := io.Pipe()
	defer func() { _ = prR.Close(); _ = pwR.Close() }()
	rootHTTP2 := errors.New(`http2: Stream closed by RST_STREAM`)
	rootBrokenPipe := errors.New("write tcp: broken pipe")

	rConn := &streamConn{
		reader:       io.NopCloser(streamConnFixedErrReader{err: rootHTTP2}),
		writer:       pwR,
		h2UploadPipe: prR,
		ctx:          context.Background(),
	}
	var buf [4]byte
	if _, err := rConn.Read(buf[:]); err == nil || !strings.Contains(err.Error(), "masque h2 dataplane connect-stream read") || !errors.Is(err, rootHTTP2) {
		t.Fatalf("expected dataplane-wrapped read with unwrap chain; got %v", err)
	}

	prW, pwW := io.Pipe()
	defer func() { _ = prW.Close(); _ = pwW.Close() }()
	wConn := &streamConn{
		reader:       io.NopCloser(streamConnFixedErrReader{errors.New("unused")}),
		writer:       errorPipeWriter{err: rootBrokenPipe},
		h2UploadPipe: prW,
		ctx:          context.Background(),
	}
	if _, err := wConn.Write([]byte("x")); err == nil || !strings.Contains(err.Error(), "masque h2 dataplane connect-stream write") || !errors.Is(err, rootBrokenPipe) {
		t.Fatalf("expected dataplane-wrapped write with unwrap chain; got %v", err)
	}
}

type errorPipeWriter struct{ err error }

func (errorPipeWriter) Close() error { return nil }
func (w errorPipeWriter) Write(_ []byte) (int, error) {
	return 0, w.err
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
	if !isRetryableTCPStreamError(&net.OpError{Op: "read", Err: syscall.ECONNRESET}) {
		t.Fatal("expected TCP ECONNRESET to be retryable for H2 CONNECT-stream")
	}
	if !isRetryableTCPStreamError(http2.ConnectionError(http2.ErrCodeProtocol)) {
		t.Fatal("expected http2 connection error to be retryable")
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
	conn := newConnectIPUDPPacketConn(context.Background(), rec, nil)
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
	conn := newConnectIPUDPPacketConn(context.Background(), rec, nil)
	_, err := conn.WriteTo([]byte("abc"), &net.UDPAddr{IP: net.ParseIP("2001:db8::2"), Port: 5601})
	if err == nil {
		t.Fatal("expected IPv6 destination rejection for temporary IPv4-only UDP bridge contract")
	}
}

func TestConnectIPUDPPacketConnWriteToSplitsLargePayload(t *testing.T) {
	rec := &recordingIPPacketSession{}
	conn := newConnectIPUDPPacketConn(context.Background(), rec, nil)
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
	conn := newConnectIPUDPPacketConn(context.Background(), rec, nil)
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

func TestConnectIPUDPPacketConnWriteToEmptySendsOnePacket(t *testing.T) {
	rec := &recordingIPPacketSession{}
	conn := newConnectIPUDPPacketConn(context.Background(), rec, nil)
	pc := conn.(*connectIPUDPPacketConn)
	dst := &net.UDPAddr{IP: net.ParseIP("10.200.0.2").To4(), Port: 5601}
	n, err := pc.WriteTo(nil, dst)
	if err != nil {
		t.Fatalf("WriteTo: %v", err)
	}
	if n != 0 {
		t.Fatalf("expected n=0, got %d", n)
	}
	if len(rec.writes) != 1 {
		t.Fatalf("expected 1 WritePacket for zero-length UDP, got %d", len(rec.writes))
	}
	pkt := rec.lastWrite
	if len(pkt) != 28 {
		t.Fatalf("expected 28-byte IPv4+UDP (empty payload), got len=%d", len(pkt))
	}
	udpLen := int(binary.BigEndian.Uint16(pkt[24:26]))
	if udpLen != 8 {
		t.Fatalf("expected UDP length 8 (header only), got %d", udpLen)
	}
}

func TestConnectIPUDPPacketConnReadFromIngressDirectBuffer(t *testing.T) {
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
	sub := &udpIngressSubscriber{ch: make(chan []byte, 1)}
	sub.ch <- packet
	pc := &connectIPUDPPacketConn{
		ingressSub:      sub,
		localV4:         netip.MustParseAddr("198.18.0.2"),
		pmtuState:       newConnectIPPMTUState(1172, 512, 1172),
		readScratchAddr: net.UDPAddr{IP: make(net.IP, 0, 16)},
	}
	buf := bytes.Repeat([]byte{0xdd}, connectIPUDPDirectReadMin)
	n, addr, err := pc.ReadFrom(buf)
	if err != nil {
		t.Fatalf("read from: %v", err)
	}
	if n != 4 || string(buf[:n]) != "pong" {
		t.Fatalf("unexpected payload after ingress copy: %q", buf[:n])
	}
	if buf[n] != 0xdd {
		t.Fatalf("expected trailing buffer prefix to stay untouched")
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
	pc := newConnectIPUDPPacketConn(context.Background(), rec, nil)
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

	session := &coreSession{
		options: ClientOptions{
			TransportMode:            "connect_udp",
			MasqueEffectiveHTTPLayer: option.MasqueHTTPLayerH3,
			TCPDial: func(ctx context.Context, network, address string) (net.Conn, error) {
				t.Fatalf("unexpected TCP dial on mocked CONNECT-UDP path")
				return nil, nil
			},
		},
		templateUDP:       templateUDP,
		capabilities:      CapabilitySet{ConnectUDP: true},
		httpLayerFallback: true,
		udpClient:         &qmasque.Client{},
		udpDial: func(ctx context.Context, client *qmasque.Client, template *uritemplate.Template, target string) (net.PacketConn, error) {
			return pc, nil
		},
	}
	session.udpHTTPLayer.Store(option.MasqueHTTPLayerH3)
	session.httpFallbackConsumed.Store(true)

	_, dialErr := session.dialUDPAddr(context.Background(), session.udpClient, templateUDP, "127.0.0.1:5353")
	if dialErr != nil {
		t.Fatalf("dialUDPAddr: %v", dialErr)
	}
	if session.httpFallbackConsumed.Load() {
		t.Fatal("expected http_fallback budget cleared after a successful CONNECT-UDP handshake on this hop")
	}
}

func TestListenPacketHTTPFallbackRunsAfterReconnectDialSwitchableFailure(t *testing.T) {
	templateUDP, err := uritemplate.New("https://example.com/masque/udp/{target_host}/{target_port}")
	if err != nil {
		t.Fatalf("build udp template: %v", err)
	}
	var call atomic.Uint32
	session := &coreSession{
		options: ClientOptions{
			TransportMode:            "connect_udp",
			MasqueEffectiveHTTPLayer: option.MasqueHTTPLayerH3,
			TCPDial: func(ctx context.Context, network, address string) (net.Conn, error) {
				return nil, errors.New("tcp dial stub")
			},
		},
		templateUDP:       templateUDP,
		capabilities:      CapabilitySet{ConnectUDP: true, ConnectIP: false},
		httpLayerFallback: true,
		udpClient:         &qmasque.Client{},
		udpDial: func(ctx context.Context, client *qmasque.Client, template *uritemplate.Template, target string) (net.PacketConn, error) {
			n := call.Add(1)
			switch n {
			case 1:
				// Must not match IsMasqueHTTPLayerSwitchableFailure substrings (would consume fallback on first dial).
				return nil, errors.New("nonswitchable_stub_udp_dial_1")
			case 2:
				return nil, errors.New("Extended CONNECT not supported on this path")
			default:
				return nil, errors.New("unexpected extra udp dial")
			}
		},
	}
	session.udpHTTPLayer.Store(option.MasqueHTTPLayerH3)

	_, listenErr := session.ListenPacket(context.Background(), M.ParseSocksaddrHostPort("127.0.0.1", 5353))
	if listenErr == nil {
		t.Fatal("expected error when hop chain is exhausted and h2 dial fails")
	}
	if len(session.hopOrder) != 0 {
		t.Fatalf("test expects no masque hop chain, got %+v index=%d", session.hopOrder, session.hopIndex)
	}
	if session.currentUDPHTTPLayer() != option.MasqueHTTPLayerH2 {
		t.Fatalf("expected http_layer fallback after reconnect dial switchable failure, overlay=%q", session.currentUDPHTTPLayer())
	}
	if call.Load() != 2 {
		t.Fatalf("expected exactly two udpDial invocations on h3 before overlay switch, got %d", call.Load())
	}
	if session.httpFallbackConsumed.Load() {
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
	var session *coreSession
	session = &coreSession{
		options: ClientOptions{
			TransportMode:            "connect_udp",
			MasqueEffectiveHTTPLayer: option.MasqueHTTPLayerH2,
			TCPDial: func(ctx context.Context, network, address string) (net.Conn, error) {
				return nil, errors.New("tcp dial stub")
			},
		},
		templateUDP:       templateUDP,
		capabilities:      CapabilitySet{ConnectUDP: true, ConnectIP: false},
		httpLayerFallback: false,
		h2UDPConnectHook: func(ctx context.Context, template *uritemplate.Template, target string) (net.PacketConn, error) {
			if session.currentUDPHTTPLayer() != option.MasqueHTTPLayerH2 {
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
		},
	}
	session.udpHTTPLayer.Store(option.MasqueHTTPLayerH2)

	pc, listenErr := session.ListenPacket(context.Background(), M.ParseSocksaddrHostPort("127.0.0.1", 5353))
	if listenErr != nil {
		t.Fatalf("ListenPacket: %v", listenErr)
	}
	if call.Load() != 2 {
		t.Fatalf("expected h2 transport churn then success (2 CONNECT-UDP attempts), got %d", call.Load())
	}
	defer pc.Close()
	if inner, ok := pc.(*masqueUDPDatagramSplitConn); !ok || inner.PacketConn != okPC {
		t.Fatalf("expected masque udp split wrapper around stub PacketConn, got %T %+v", pc, pc)
	}
}

func TestDialTCPStreamHTTPFallbackRunsAfterReconnectRoundTripSwitchableFailure(t *testing.T) {
	var h3RoundTrips atomic.Uint32
	session := &coreSession{
		options: ClientOptions{
			Server:                   "example.com",
			ServerPort:               443,
			TemplateTCP:              "https://example.com/masque/tcp/{target_host}/{target_port}",
			TransportMode:            "connect_udp",
			MasqueEffectiveHTTPLayer: option.MasqueHTTPLayerH3,
			TCPDial: func(ctx context.Context, network, address string) (net.Conn, error) {
				return nil, errors.New("tcp dial stub")
			},
		},
		capabilities:      CapabilitySet{ConnectTCP: true},
		httpLayerFallback: true,
	}
	session.tcpRoundTripper = roundTripperFunc(func(req *http.Request) (*http.Response, error) {
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
	session.udpHTTPLayer.Store(option.MasqueHTTPLayerH3)

	_, dialErr := session.dialTCPStream(context.Background(), M.ParseSocksaddrHostPort("example.com", 443))
	if dialErr == nil {
		t.Fatal("expected error once h2 path hits tcp dial stub")
	}
	if len(session.hopOrder) != 0 {
		t.Fatalf("test expects no masque hop chain, got %+v", session.hopOrder)
	}
	if session.currentUDPHTTPLayer() != option.MasqueHTTPLayerH2 {
		t.Fatalf("expected http_layer fallback after transport churn exposes switchable failure, overlay=%q", session.currentUDPHTTPLayer())
	}
	if got := h3RoundTrips.Load(); got != 2 {
		t.Fatalf("expected exactly two CONNECT-stream RoundTrips on overlay h3 before switch, got %d", got)
	}
	if session.httpFallbackConsumed.Load() {
		t.Fatal("expected httpFallbackConsumed cleared after exhausted dialTCPStream so retries can pivot again")
	}
}

func TestOpenIPSessionFailureClearsHTTPFallbackLatchForNextAttempt(t *testing.T) {
	templateIP, err := uritemplate.New("https://example.com/masque/ip")
	if err != nil {
		t.Fatalf("build ip template: %v", err)
	}
	session := &coreSession{
		options: ClientOptions{
			TransportMode:            "connect_ip",
			MasqueEffectiveHTTPLayer: option.MasqueHTTPLayerH3,
		},
		templateIP:        templateIP,
		capabilities:      CapabilitySet{ConnectIP: true},
		httpLayerFallback: true,
		dialConnectIPAttemptHook: func(ctx context.Context, useHTTP2 bool) (*connectip.Conn, error) {
			if !useHTTP2 {
				return nil, errors.New("Extended CONNECT not supported")
			}
			return nil, errors.New("stub h2 connect-ip non-switchable failure")
		},
	}
	session.udpHTTPLayer.Store(option.MasqueHTTPLayerH3)

	_, openErr := session.OpenIPSession(context.Background())
	if openErr == nil {
		t.Fatal("expected error from stubbed connect-ip dials")
	}
	if session.httpFallbackConsumed.Load() {
		t.Fatal("expected httpFallbackConsumed cleared after a wholly failed open so the next try can pivot again")
	}
}

func TestOpenIPSessionHTTPFallbackRunsAfterIPH3ReconnectDialSwitchableFailure(t *testing.T) {
	templateIP, err := uritemplate.New("https://example.com/masque/ip")
	if err != nil {
		t.Fatalf("build ip template: %v", err)
	}
	var call atomic.Uint32
	session := &coreSession{
		options: ClientOptions{
			TransportMode:            "connect_ip",
			MasqueEffectiveHTTPLayer: option.MasqueHTTPLayerH3,
		},
		templateIP:        templateIP,
		capabilities:      CapabilitySet{ConnectIP: true},
		httpLayerFallback: true,
		dialConnectIPAttemptHook: func(ctx context.Context, useHTTP2 bool) (*connectip.Conn, error) {
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
		},
	}
	session.udpHTTPLayer.Store(option.MasqueHTTPLayerH3)

	_, openErr := session.OpenIPSession(context.Background())
	if openErr == nil {
		t.Fatal("expected error when h2 connect-ip dial is stubbed to fail")
	}
	if session.currentUDPHTTPLayer() != option.MasqueHTTPLayerH2 {
		t.Fatalf("expected http_layer fallback after iph3 reconnect switchable failure, overlay=%q", session.currentUDPHTTPLayer())
	}
	// 2× H3 (nonswitchable + after ipHTTP churn), 1× H3→H2 fallback dial, 1× H2 transport churn redial.
	if call.Load() != 4 {
		t.Fatalf("expected four connect_ip stub invocations, got %d", call.Load())
	}
}

func TestOpenIPSessionH2TransportChurnBeforeHopPivot(t *testing.T) {
	templateIP, err := uritemplate.New("https://example.com/masque/ip")
	if err != nil {
		t.Fatalf("build ip template: %v", err)
	}
	okConn := &connectip.Conn{}
	var call atomic.Uint32
	session := &coreSession{
		options: ClientOptions{
			TransportMode:            "connect_ip",
			MasqueEffectiveHTTPLayer: option.MasqueHTTPLayerH2,
			TCPDial: func(ctx context.Context, network, address string) (net.Conn, error) {
				return nil, errors.New("tcp dial stub")
			},
		},
		templateIP:        templateIP,
		capabilities:      CapabilitySet{ConnectIP: true},
		httpLayerFallback: false,
		dialConnectIPAttemptHook: func(ctx context.Context, useHTTP2 bool) (*connectip.Conn, error) {
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
		},
	}
	session.udpHTTPLayer.Store(option.MasqueHTTPLayerH2)

	sess, openErr := session.OpenIPSession(context.Background())
	if openErr != nil {
		t.Fatalf("open ip session: %v", openErr)
	}
	if call.Load() != 2 {
		t.Fatalf("expected h2 churn then success (2 connect-ip attempts), got %d", call.Load())
	}
	ps, ok := sess.(*connectIPPacketSession)
	if !ok || ps.conn != okConn {
		t.Fatalf("unexpected session wrapper: %T / conn=%v", sess, ps)
	}
}

func TestDialConnectIPHTTP2ReturnsCanceledBeforeTCPConfig(t *testing.T) {
	templateIP, err := uritemplate.New("https://example.com/masque/ip")
	if err != nil {
		t.Fatalf("build ip template: %v", err)
	}
	s := &coreSession{
		options: ClientOptions{
			Tag:    "t",
			Server: "127.0.0.1",
			// Intentionally no TCPDial: a canceled dial must not surface as missing dialer before ctx cause.
			ServerPort: 443,
		},
		templateIP: templateIP,
	}
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
	s := &coreSession{
		options: ClientOptions{
			Tag:        "t",
			Server:     "127.0.0.1",
			ServerPort: 443,
			TCPDial: func(context.Context, string, string) (net.Conn, error) {
				return nil, errors.New("unreachable tcp dial")
			},
		},
		templateIP: nil,
	}
	_, dialErr := s.dialConnectIPHTTP2(context.Background())
	if dialErr == nil {
		t.Fatal("expected error")
	}
	if !errors.Is(dialErr, ErrConnectIPTemplateNotConfigured) {
		t.Fatalf("unexpected err: %v", dialErr)
	}
	if IsMasqueHTTPLayerSwitchableFailure(dialErr) {
		t.Fatal("missing IP template must not imply http_layer_fallback")
	}
}

func TestDialUDPOverHTTP2ReturnsCanceledBeforeTCPConfig(t *testing.T) {
	templateUDP, err := uritemplate.New("https://example.com/masque/udp/{target_host}/{target_port}")
	if err != nil {
		t.Fatalf("build udp template: %v", err)
	}
	s := &coreSession{
		options: ClientOptions{
			Tag:        "t",
			Server:     "127.0.0.1",
			ServerPort: 443,
			// No TCPDial: canceled ctx must yield Cause before tcp dialer error.
		},
	}
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
	s := &coreSession{
		options: ClientOptions{
			Tag:        "t",
			Server:     "127.0.0.1",
			ServerPort: 443,
		},
	}
	_, dialErr := s.dialUDPOverHTTP2(context.Background(), nil, "8.8.8.8:53")
	if dialErr == nil {
		t.Fatal("expected error")
	}
	if !errors.Is(dialErr, ErrConnectUDPTemplateNotConfigured) {
		t.Fatalf("unexpected err: %v", dialErr)
	}
	if IsMasqueHTTPLayerSwitchableFailure(dialErr) {
		t.Fatal("nil template is a config error; must not imply http_layer_fallback")
	}
}

func TestDialUDPAddrH3ReturnsErrWhenTemplateNil(t *testing.T) {
	s := &coreSession{
		options: ClientOptions{
			Tag:        "t",
			Server:     "127.0.0.1",
			ServerPort: 443,
		},
	}
	s.udpHTTPLayer.Store(option.MasqueHTTPLayerH3)
	cli := &qmasque.Client{}
	_, dialErr := s.dialUDPAddr(context.Background(), cli, nil, "8.8.8.8:53")
	if dialErr == nil {
		t.Fatal("expected error")
	}
	if !errors.Is(dialErr, ErrConnectUDPTemplateNotConfigured) {
		t.Fatalf("unexpected err: %v", dialErr)
	}
	if IsMasqueHTTPLayerSwitchableFailure(dialErr) {
		t.Fatal("nil template is a config error; must not imply http_layer_fallback")
	}
}

func TestDialUDPAddrH2ReturnsErrWhenTemplateNil(t *testing.T) {
	s := &coreSession{
		options: ClientOptions{
			Tag:        "t",
			Server:     "127.0.0.1",
			ServerPort: 443,
			TCPDial: func(context.Context, string, string) (net.Conn, error) {
				return nil, errors.New("unreachable tcp dial")
			},
		},
	}
	s.udpHTTPLayer.Store(option.MasqueHTTPLayerH2)
	s.h2UDPConnectHook = func(context.Context, *uritemplate.Template, string) (net.PacketConn, error) {
		t.Fatal("dialUDPOverHTTP2 hook must not run when UDP template is nil")
		return nil, nil
	}
	_, dialErr := s.dialUDPAddr(context.Background(), nil, nil, "8.8.8.8:53")
	if dialErr == nil {
		t.Fatal("expected error")
	}
	if !errors.Is(dialErr, ErrConnectUDPTemplateNotConfigured) {
		t.Fatalf("unexpected err: %v", dialErr)
	}
	if IsMasqueHTTPLayerSwitchableFailure(dialErr) {
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
	s := &coreSession{options: opts}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, dialErr := s.dialTCPStreamH2(ctx, u, opts, "example.com", M.Socksaddr{})
	if dialErr == nil {
		t.Fatal("expected error")
	}
	if !errors.Is(dialErr, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", dialErr)
	}
	if !errors.Is(dialErr, ErrTCPConnectStreamFailed) {
		t.Fatalf("expected ErrTCPConnectStreamFailed joined, got %v", dialErr)
	}
}

// H2 CONNECT-stream must join ErrTCPConnectStreamFailed for early transport failures (parity with H3 and with in-loop errors).
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
	s := &coreSession{options: opts}
	_, dialErr := s.dialTCPStreamH2(context.Background(), u, opts, "example.com", M.Socksaddr{Port: 443})
	if dialErr == nil {
		t.Fatal("expected error")
	}
	if !errors.Is(dialErr, ErrTCPConnectStreamFailed) {
		t.Fatalf("expected ErrTCPConnectStreamFailed joined, got %v", dialErr)
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
	s := &coreSession{options: opts}
	var attempts atomic.Uint32
	ctx, cancel := context.WithCancel(context.Background())
	s.tcpRoundTripper = roundTripperFunc(func(*http.Request) (*http.Response, error) {
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
	if !errors.Is(dialErr, ErrTCPConnectStreamFailed) {
		t.Fatalf("expected ErrTCPConnectStreamFailed joined, got %v", dialErr)
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
	s := &coreSession{options: opts}
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
	s.tcpRoundTripper = roundTripperFunc(func(*http.Request) (*http.Response, error) {
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
	s := &coreSession{
		options: ClientOptions{
			Tag:        "t",
			Server:     "127.0.0.1",
			ServerPort: 443,
		},
	}
	s.udpHTTPLayer.Store(option.MasqueHTTPLayerH3)
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
	s := &coreSession{
		options: ClientOptions{
			Tag:        "t",
			Server:     "127.0.0.1",
			ServerPort: 443,
			TCPDial: func(context.Context, string, string) (net.Conn, error) {
				return nil, errors.New("unreachable tcp dial")
			},
		},
	}
	s.h2UDPConnectHook = func(context.Context, *uritemplate.Template, string) (net.PacketConn, error) {
		t.Fatal("dialUDPOverHTTP2 path should not run when ctx already canceled")
		return nil, nil
	}
	s.udpHTTPLayer.Store(option.MasqueHTTPLayerH2)
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
	s := &coreSession{
		options: ClientOptions{
			Tag:        "t",
			Server:     "127.0.0.1",
			ServerPort: 443,
		},
		templateIP: nil,
	}
	_, dialErr := s.dialConnectIPAttempt(context.Background(), false)
	if dialErr == nil {
		t.Fatal("expected error")
	}
	if !errors.Is(dialErr, ErrConnectIPTemplateNotConfigured) {
		t.Fatalf("unexpected err: %v", dialErr)
	}
	if IsMasqueHTTPLayerSwitchableFailure(dialErr) {
		t.Fatal("missing IP template must not imply http_layer_fallback")
	}
}

func TestDialConnectIPAttemptH3ReturnsCanceledBeforeLayerLog(t *testing.T) {
	templateIP, err := uritemplate.New("https://example.com/masque/ip")
	if err != nil {
		t.Fatalf("build ip template: %v", err)
	}
	s := &coreSession{
		options: ClientOptions{
			Tag:        "t",
			Server:     "127.0.0.1",
			ServerPort: 443,
		},
		templateIP: templateIP,
	}
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
	s := &coreSession{
		options: ClientOptions{
			Tag:        "t",
			Server:     "127.0.0.1",
			ServerPort: 443,
			TCPDial: func(context.Context, string, string) (net.Conn, error) {
				t.Fatal("TCPDial must not run when ctx already canceled before CONNECT-IP H2 dial")
				return nil, nil
			},
		},
		templateIP: templateIP,
	}
	s.httpFallbackConsumed.Store(true)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, dialErr := s.dialConnectIPAttempt(ctx, true)
	if dialErr == nil {
		t.Fatal("expected error")
	}
	if !errors.Is(dialErr, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", dialErr)
	}
	if s.httpFallbackConsumed.Load() {
		t.Fatal("expected httpFallbackConsumed cleared on early cancel before H2 CONNECT-IP (parity with H3)")
	}
}

// Parity with openIPSessionLocked: cached HTTP/3 client conn must not short-circuit a canceled ctx.
func TestOpenHTTP3ClientConnReturnsCanceledBeforeReuse(t *testing.T) {
	s := &coreSession{
		options: ClientOptions{
			Tag:        "t",
			Server:     "127.0.0.1",
			ServerPort: 443,
		},
		ipHTTPConn: new(http3.ClientConn),
	}
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

// Parity with openHTTP3ClientConn: cached HTTP/2 overlay transport must not short-circuit a canceled ctx.
func TestEnsureH2UDPTransportReturnsCanceledBeforeReuse(t *testing.T) {
	s := &coreSession{
		options: ClientOptions{
			Tag:        "t",
			Server:     "127.0.0.1",
			ServerPort: 443,
			TCPDial: func(context.Context, string, string) (net.Conn, error) {
				return nil, errors.New("unreachable")
			},
		},
		h2UdpTransport: &http2.Transport{},
	}
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
	s := &coreSession{
		options:      ClientOptions{Tag: "t"},
		capabilities: CapabilitySet{ConnectIP: true},
		ipConn:       &connectip.Conn{},
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	s.mu.Lock()
	_, openErr := s.openIPSessionLocked(ctx)
	s.mu.Unlock()
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
	s := &coreSession{
		options: ClientOptions{
			Tag:        "t",
			Server:     "hop1.example",
			ServerPort: 443,
			Hops: []HopOptions{
				{Tag: "h1", Server: "hop1.example", Port: 443},
				{Tag: "h2", Via: "h1", Server: "hop2.example", Port: 8443},
			},
		},
		hopOrder: []HopOptions{
			{Tag: "h1", Server: "hop1.example", Port: 443},
			{Tag: "h2", Via: "h1", Server: "hop2.example", Port: 8443},
		},
		hopIndex:     0,
		capabilities: CapabilitySet{ConnectIP: true},
		templateIP:   templateIP,
	}
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
	s.mu.Lock()
	_, openErr := s.openIPSessionLocked(ctx)
	s.mu.Unlock()
	if openErr == nil {
		t.Fatal("expected error")
	}
	if !errors.Is(openErr, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", openErr)
	}
	if s.hopIndex != 0 {
		t.Fatalf("expected hopIndex to stay 0 on cancel, got %d", s.hopIndex)
	}
	if s.options.Server != "hop1.example" || s.options.ServerPort != 443 {
		t.Fatalf("expected session to remain on first hop, got %s:%d", s.options.Server, s.options.ServerPort)
	}
}

// After a non-cancel failure on the entry hop, cancellation on a subsequent inner-hop CONNECT-IP dial
// must return before the next advanceHop() consumes another chain entry.
func TestOpenIPSessionLockedCanceledDialInnerLoopDoesNotAdvanceHopAgain(t *testing.T) {
	templateIP, err := uritemplate.New("https://hop1.example/masque/ip")
	if err != nil {
		t.Fatalf("template: %v", err)
	}
	s := &coreSession{
		options: ClientOptions{
			Tag:        "t",
			Server:     "hop1.example",
			ServerPort: 443,
			Hops: []HopOptions{
				{Tag: "h1", Server: "hop1.example", Port: 443},
				{Tag: "h2", Via: "h1", Server: "hop2.example", Port: 8443},
				{Tag: "h3", Via: "h2", Server: "hop3.example", Port: 8444},
			},
		},
		hopOrder: []HopOptions{
			{Tag: "h1", Server: "hop1.example", Port: 443},
			{Tag: "h2", Via: "h1", Server: "hop2.example", Port: 8443},
			{Tag: "h3", Via: "h2", Server: "hop3.example", Port: 8444},
		},
		hopIndex:     0,
		capabilities: CapabilitySet{ConnectIP: true},
		templateIP:   templateIP,
	}
	secondDialEntered := make(chan struct{})
	var enteredOnce sync.Once
	ctx, cancel := context.WithCancel(context.Background())
	s.dialConnectIPAttemptHook = func(dialCtx context.Context, _ bool) (*connectip.Conn, error) {
		if s.hopIndex == 0 {
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
	s.mu.Lock()
	_, openErr := s.openIPSessionLocked(ctx)
	s.mu.Unlock()
	if openErr == nil {
		t.Fatal("expected error")
	}
	if !errors.Is(openErr, context.Canceled) {
		t.Fatalf("expected context.Canceled in error chain, got %v", openErr)
	}
	if s.hopIndex != 1 {
		t.Fatalf("expected exactly one hop advance before cancel, hopIndex=%d", s.hopIndex)
	}
	if s.options.Server != "hop2.example" || s.options.ServerPort != 8443 {
		t.Fatalf("expected logical hop h2 after single advance, got %s:%d", s.options.Server, s.options.ServerPort)
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
	s := &coreSession{options: opts}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, dialErr := s.dialTCPStreamHTTP3(ctx, u, opts, "example.com", 80, nil)
	if dialErr == nil {
		t.Fatal("expected error")
	}
	if !errors.Is(dialErr, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", dialErr)
	}
	if !errors.Is(dialErr, ErrTCPConnectStreamFailed) {
		t.Fatalf("expected ErrTCPConnectStreamFailed joined, got %v", dialErr)
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
	s := &coreSession{options: opts}
	var attempts atomic.Uint32
	ctx, cancel := context.WithCancel(context.Background())
	s.tcpRoundTripper = roundTripperFunc(func(*http.Request) (*http.Response, error) {
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
	if !errors.Is(dialErr, ErrTCPConnectStreamFailed) {
		t.Fatalf("expected ErrTCPConnectStreamFailed joined, got %v", dialErr)
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
	okConn := &connectip.Conn{}
	session := &coreSession{
		options: ClientOptions{
			TransportMode: "connect_ip",
		},
		templateIP:   templateIP,
		capabilities: CapabilitySet{ConnectIP: true},
		dialConnectIPAttemptHook: func(ctx context.Context, useHTTP2 bool) (*connectip.Conn, error) {
			return okConn, nil
		},
	}
	session.udpHTTPLayer.Store(option.MasqueHTTPLayerH3)

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
	okConn := &connectip.Conn{}
	ctx, cancel := context.WithCancel(context.Background())
	session := &coreSession{
		options: ClientOptions{
			TransportMode: "connect_ip",
		},
		templateIP:   templateIP,
		capabilities: CapabilitySet{ConnectIP: true},
		dialConnectIPAttemptHook: func(context.Context, bool) (*connectip.Conn, error) {
			return okConn, nil
		},
		listenPacketPostOpenIPSessionUnlockHook: func() { cancel() },
	}
	session.udpHTTPLayer.Store(option.MasqueHTTPLayerH3)
	// Exercise full abandon teardown: overlay transports must not outlive the closed connect-ip.Conn.
	session.ipHTTP = &http3.Transport{}
	session.h2UdpMu.Lock()
	session.h2UdpTransport = &http2.Transport{}
	session.h2UdpMu.Unlock()

	_, listenErr := session.ListenPacket(ctx, M.Socksaddr{})
	if listenErr == nil || !errors.Is(listenErr, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", listenErr)
	}
	if session.ipConn != nil {
		t.Fatal("expected released ipConn after cancel before PacketConn wrap")
	}
	if session.ipHTTP != nil || session.ipHTTPConn != nil {
		t.Fatal("expected resetIPH3 after abandon before PacketConn wrap")
	}
	session.h2UdpMu.Lock()
	h2Left := session.h2UdpTransport
	session.h2UdpMu.Unlock()
	if h2Left != nil {
		t.Fatal("expected H2 overlay pool cleared after abandon before PacketConn wrap")
	}
}

func TestReleaseOpenedConnectIPSessionIfAbandonedClearsHTTPLayers(t *testing.T) {
	s := &coreSession{options: ClientOptions{}}
	s.ipConn = &connectip.Conn{}
	s.ipHTTP = &http3.Transport{}
	s.h2UdpMu.Lock()
	s.h2UdpTransport = &http2.Transport{}
	s.h2UdpMu.Unlock()

	s.releaseOpenedConnectIPSessionIfAbandoned()

	if s.ipConn != nil || s.ipHTTP != nil || s.ipHTTPConn != nil {
		t.Fatalf("expected CONNECT-IP plane and HTTP/3 refs cleared, ipConn=%v ipHTTP=%v", s.ipConn, s.ipHTTP)
	}
	s.h2UdpMu.Lock()
	h2Left := s.h2UdpTransport
	s.h2UdpMu.Unlock()
	if h2Left != nil {
		t.Fatal("expected h2UdpTransport cleared")
	}
}

func TestListenPacketConnectIPCanceledBeforeOpenIPSessions(t *testing.T) {
	var hookCalls atomic.Uint32
	okConn := &connectip.Conn{}
	session := &coreSession{
		options:      ClientOptions{TransportMode: "connect_ip"},
		capabilities: CapabilitySet{ConnectIP: true},
		dialConnectIPAttemptHook: func(context.Context, bool) (*connectip.Conn, error) {
			hookCalls.Add(1)
			return okConn, nil
		},
	}
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
	okConn := &connectip.Conn{}
	session := &coreSession{
		options:      ClientOptions{TransportMode: "connect_ip"},
		capabilities: CapabilitySet{ConnectIP: true},
		dialConnectIPAttemptHook: func(context.Context, bool) (*connectip.Conn, error) {
			hookCalls.Add(1)
			return okConn, nil
		},
	}
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
	s := &coreSession{
		options: ClientOptions{
			TransportMode: option.MasqueTransportModeConnectUDP,
		},
		udpClient:    &qmasque.Client{},
		templateUDP:  templateUDP,
		capabilities: CapabilitySet{ConnectUDP: true},
		udpDial: func(context.Context, *qmasque.Client, *uritemplate.Template, string) (net.PacketConn, error) {
			dials.Add(1)
			return nil, errors.New("unexpected dial")
		},
	}
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
	s := &coreSession{
		options: ClientOptions{
			TransportMode: option.MasqueTransportModeConnectUDP,
		},
		udpClient:    &qmasque.Client{},
		templateUDP:  templateUDP,
		capabilities: CapabilitySet{ConnectUDP: true},
		udpDial: func(context.Context, *qmasque.Client, *uritemplate.Template, string) (net.PacketConn, error) {
			dials.Add(1)
			return nil, errors.New("unexpected dial")
		},
		listenPacketPreResolveDestinationHook: func() { cancel() },
	}
	_, listenErr := s.ListenPacket(ctx, M.ParseSocksaddrHostPort("127.0.0.1", 53))
	if listenErr == nil || !errors.Is(listenErr, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", listenErr)
	}
	if dials.Load() != 0 {
		t.Fatalf("udpDial called %d times", dials.Load())
	}
}

func TestDialContextCanceledBeforeTCPBranches(t *testing.T) {
	s := &coreSession{
		options: ClientOptions{
			TCPTransport: option.MasqueTCPTransportConnectStream,
		},
	}
	s.httpFallbackConsumed.Store(true)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := s.DialContext(ctx, "tcp", M.ParseSocksaddrHostPort("127.0.0.1", 443))
	if err == nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
	if s.httpFallbackConsumed.Load() {
		t.Fatal("expected httpFallbackConsumed cleared on early cancel before dialTCPStream (parity with ListenPacket/OpenIPSession)")
	}
}

func TestDialConnectIPTCPCanceledClearsHTTPFallbackLatch(t *testing.T) {
	s := &coreSession{
		capabilities: CapabilitySet{ConnectIP: true},
		options: ClientOptions{
			TransportMode: option.MasqueTransportModeConnectIP,
			TCPTransport:  option.MasqueTCPTransportConnectIP,
			Server:        "127.0.0.1",
			ServerPort:    443,
		},
	}
	s.httpFallbackConsumed.Store(true)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := s.dialConnectIPTCP(ctx, M.ParseSocksaddrHostPort("127.0.0.1", 443))
	if err == nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
	if s.httpFallbackConsumed.Load() {
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
			Server:         "masque.local",
			ServerPort:     443,
			TemplateTCP:    "https://masque.local/masque/tcp/{target_host}/{target_port}",
			TCPTransport:   "connect_stream",
			TCPMode:        option.MasqueTCPModeMasqueOrDirect,
			FallbackPolicy: option.MasqueFallbackPolicyDirectExplicit,
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
			Server:         "masque.local",
			ServerPort:     443,
			TemplateTCP:    "https://masque.local/masque/tcp/{target_host}/{target_port}",
			TCPTransport:   "connect_stream",
			TCPMode:        option.MasqueTCPModeMasqueOrDirect,
			FallbackPolicy: option.MasqueFallbackPolicyDirectExplicit,
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
			Server:         "masque.local",
			ServerPort:     443,
			TemplateTCP:    "https://masque.local/masque/tcp/{target_host}/{target_port}",
			TCPTransport:   "connect_stream",
			TCPMode:        option.MasqueTCPModeStrictMasque,
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
		"timeout_while_connecting":   timeoutNetError{msg: "timeout while connecting"},
		"no_recent_network_activity": &quic.IdleTimeoutError{},
		"idle_timeout_reached":       timeoutNetError{msg: "idle timeout reached"},
		"application_error_0x100":    &quic.ApplicationError{ErrorCode: 0x100, Remote: true},
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

func TestDialTCPStreamPreAdvanceHopJoinsCauseWhenCanceledAtChainEnd(t *testing.T) {
	handshakeErr := errors.New("handshake before hop advance cancel")
	ctx, cancel := context.WithCancel(context.Background())
	session := &coreSession{
		options: ClientOptions{
			Server:      "masque.local",
			ServerPort:  443,
			TemplateTCP: "https://masque.local/masque/tcp/{target_host}/{target_port}",
		},
		tcpRoundTripper: roundTripperFunc(func(*http.Request) (*http.Response, error) {
			return nil, handshakeErr
		}),
		dialTCPStreamPreAdvanceHopHook: func() { cancel() },
	}
	session.udpHTTPLayer.Store(option.MasqueHTTPLayerH3)
	_, err := session.dialTCPStream(ctx, M.ParseSocksaddrHostPort("example.com", 443))
	if !errors.Is(err, ErrTCPConnectStreamFailed) || !errors.Is(err, context.Canceled) || !errors.Is(err, handshakeErr) {
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
	s := &coreSession{
		options: ClientOptions{
			TransportMode: option.MasqueTransportModeConnectUDP,
		},
		udpClient:    &qmasque.Client{},
		templateUDP:  templateUDP,
		capabilities: CapabilitySet{ConnectUDP: true},
		udpDial: func(context.Context, *qmasque.Client, *uritemplate.Template, string) (net.PacketConn, error) {
			return nil, dialUDPfail
		},
		listenPacketPreChainEndReturnHook: func() { cancel() },
	}
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
	session := &coreSession{
		options: ClientOptions{
			Server:      "masque.local",
			ServerPort:  443,
			TemplateTCP: "https://masque.local/masque/tcp/{target_host}/{target_port}",
		},
		tcpRoundTripper: roundTripperFunc(func(*http.Request) (*http.Response, error) {
			close(entered)
			<-resume
			return nil, handshakeErr
		}),
	}
	session.udpHTTPLayer.Store(option.MasqueHTTPLayerH3)
	go func() {
		<-entered
		cancel()
		close(resume)
	}()
	_, err := session.dialTCPStream(ctx, M.ParseSocksaddrHostPort("example.com", 443))
	if !errors.Is(err, ErrTCPConnectStreamFailed) {
		t.Fatalf("expected ErrTCPConnectStreamFailed in chain, got: %v", err)
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
		Server:       "127.0.0.1",
		ServerPort:   uint16(proxyPort),
		Insecure:     true,
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

func TestSnapshotMetricsTracksDialSuccessFallbackStackReady(t *testing.T) {
	before := SnapshotMetrics()
	recordTCPDialSuccess()
	recordTCPDialSuccess()
	recordTCPFallback()
	recordConnectIPStackReady(true)
	recordConnectIPStackReady(false)
	after := SnapshotMetrics()
	if after.TCPDialTotal < before.TCPDialTotal+2 {
		t.Fatalf("tcp_dial_total: before=%d after=%d", before.TCPDialTotal, after.TCPDialTotal)
	}
	if after.TCPFallbackTotal < before.TCPFallbackTotal+1 {
		t.Fatalf("tcp_fallback_total: before=%d after=%d", before.TCPFallbackTotal, after.TCPFallbackTotal)
	}
	if after.ConnectIPStackReady < before.ConnectIPStackReady+1 {
		t.Fatalf("connect_ip_stack_ready_total: before=%d after=%d", before.ConnectIPStackReady, after.ConnectIPStackReady)
	}
	if after.ConnectIPStackNotReady < before.ConnectIPStackNotReady+1 {
		t.Fatalf("connect_ip_stack_not_ready_total: before=%d after=%d", before.ConnectIPStackNotReady, after.ConnectIPStackNotReady)
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
