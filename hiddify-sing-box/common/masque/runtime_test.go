package masque

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"net"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	connectip "github.com/quic-go/connect-ip-go"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/transport/masque/session"
	mcip "github.com/sagernet/sing-box/transport/masque/connectip"
	T "github.com/sagernet/sing-box/transport/masque"
	M "github.com/sagernet/sing/common/metadata"
)

type testIPSession struct{}

func (s *testIPSession) ReadPacket(buffer []byte) (int, error) { return 0, nil }
func (s *testIPSession) WritePacket(buffer []byte) ([]byte, error) {
	return nil, nil
}
func (s *testIPSession) Close() error { return nil }

type testSession struct {
	ip          T.IPPacketSession
	dialErr     error
	ipErr       error
	openIPCalls atomic.Int32
}

func (s *testSession) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	if s.dialErr != nil {
		return nil, s.dialErr
	}
	return nil, nil
}
func (s *testSession) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return nil, nil
}
func (s *testSession) OpenIPSession(ctx context.Context) (T.IPPacketSession, error) {
	s.openIPCalls.Add(1)
	if err := ctx.Err(); err != nil {
		return nil, context.Cause(ctx)
	}
	if s.ipErr != nil {
		return nil, s.ipErr
	}
	return s.ip, nil
}
func (s *testSession) Capabilities() T.CapabilitySet { return T.CapabilitySet{ConnectIP: true} }
func (s *testSession) Close() error                  { return nil }

type testFactory struct {
	session T.ClientSession
}

func (f testFactory) NewSession(ctx context.Context, options T.ClientOptions) (T.ClientSession, error) {
	return f.session, nil
}

// captureOptsFactory records the last ClientOptions passed to NewSession (for dial-identity normalization tests).
type captureOptsFactory struct {
	last T.ClientOptions
}

func (f *captureOptsFactory) NewSession(ctx context.Context, options T.ClientOptions) (T.ClientSession, error) {
	f.last = options
	return &testSession{}, nil
}

type errSessionFactory struct {
	err error
}

func (f errSessionFactory) NewSession(ctx context.Context, options T.ClientOptions) (T.ClientSession, error) {
	return nil, f.err
}

type countingErrSessionFactory struct {
	err      error
	attempts int32
}

func (f *countingErrSessionFactory) NewSession(ctx context.Context, options T.ClientOptions) (T.ClientSession, error) {
	atomic.AddInt32(&f.attempts, 1)
	return nil, f.err
}

func (f *countingErrSessionFactory) Attempts() int {
	return int(atomic.LoadInt32(&f.attempts))
}

// cancelProbeFactory fails NewSession when ctx is already cancelled (models transport respecting router/box ctx).
type cancelProbeFactory struct{}

func (cancelProbeFactory) NewSession(ctx context.Context, options T.ClientOptions) (T.ClientSession, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return &testSession{}, nil
}

func TestRuntimeNewSessionTrimsDialIdentityStrings(t *testing.T) {
	f := &captureOptsFactory{}
	rt := NewRuntime(f, RuntimeOptions{
		Server:              "  edge.example \t",
		DialPeer:            "  192.0.2.1 ",
		ServerPort:          443,
		ServerToken:         "  tok  ",
		MasqueQUICCryptoTLS: &tls.Config{ServerName: " sni.example "},
	})
	if err := rt.Start(context.Background()); err != nil {
		t.Fatalf("start: %v", err)
	}
	if f.last.Server != "edge.example" {
		t.Fatalf("server: got %q", f.last.Server)
	}
	if f.last.DialPeer != "192.0.2.1" {
		t.Fatalf("dial peer: got %q", f.last.DialPeer)
	}
	if f.last.ServerToken != "tok" {
		t.Fatalf("token: got %q", f.last.ServerToken)
	}
	if f.last.MasqueQUICCryptoTLS == nil || f.last.MasqueQUICCryptoTLS.ServerName != " sni.example " {
		got := ""
		if f.last.MasqueQUICCryptoTLS != nil {
			got = f.last.MasqueQUICCryptoTLS.ServerName
		}
		t.Fatalf("sni: got %q", got)
	}
}

func TestRuntimeStartUsesCancelledRouterContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	rt := NewRuntime(cancelProbeFactory{}, RuntimeOptions{})
	startErr := rt.Start(ctx)
	if !errors.Is(startErr, context.Canceled) {
		t.Fatalf("expected context.Canceled from cancelled start ctx, got: %v", startErr)
	}
	if rt.LifecycleState() != StateDegraded {
		t.Fatalf("expected degraded after cancelled start, got: %v", rt.LifecycleState())
	}
	if le := rt.LastError(); le == nil || !errors.Is(le, context.Canceled) {
		t.Fatalf("expected LastError to hold cancel cause, got: %v", le)
	}
	if got := session.ClassifyError(startErr); got != session.ErrorClassLifecycle {
		t.Fatalf("expected lifecycle class for cancelled start, got: %s", got)
	}
}

func TestRuntimeLastErrorOnStartFailure(t *testing.T) {
	rt := NewRuntime(errSessionFactory{err: errors.New("dial refused")}, RuntimeOptions{})
	if err := rt.Start(context.Background()); err == nil {
		t.Fatal("expected start error")
	}
	if rt.IsReady() {
		t.Fatal("expected not ready")
	}
	if rt.LifecycleState() != StateDegraded {
		t.Fatalf("lifecycle state: %v", rt.LifecycleState())
	}
	if rt.LastError() == nil {
		t.Fatal("expected LastError after failed Start")
	}
}

func TestRuntimeStartRetryBudgetDeterministicThreeAttempts(t *testing.T) {
	factory := &countingErrSessionFactory{
		err: errors.Join(session.ErrTransportInit, errors.New("quic handshake failed")),
	}
	rt := NewRuntime(factory, RuntimeOptions{})
	startErr := rt.Start(context.Background())
	if startErr == nil {
		t.Fatal("expected start to fail and exhaust retry budget")
	}
	if !errors.Is(startErr, session.ErrTransportInit) {
		t.Fatalf("expected transport init cause after retry budget exhaustion, got: %v", startErr)
	}
	if gotAttempts := factory.Attempts(); gotAttempts != 3 {
		t.Fatalf("expected runtime start retry budget=3 attempts, got: %d", gotAttempts)
	}
	if rt.LifecycleState() != StateDegraded {
		t.Fatalf("expected degraded after retry budget exhaustion, got: %v", rt.LifecycleState())
	}
}

func TestRuntimeStartCancelledDuringBackoffStopsFurtherAttempts(t *testing.T) {
	factory := &countingErrSessionFactory{
		err: errors.Join(session.ErrTransportInit, errors.New("transient transport bootstrap failure")),
	}
	rt := NewRuntime(factory, RuntimeOptions{})
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		// Cancel while Start waits in reconnect backoff (attempt=1 -> 100ms),
		// so retry loop must terminate before making second NewSession call.
		time.Sleep(20 * time.Millisecond)
		cancel()
	}()
	startErr := rt.Start(ctx)
	if startErr == nil {
		t.Fatal("expected start cancellation during retry backoff")
	}
	if !errors.Is(startErr, context.Canceled) {
		t.Fatalf("expected context canceled cause from start cancellation, got: %v", startErr)
	}
	if !errors.Is(startErr, session.ErrLifecycleClosed) {
		t.Fatalf("expected lifecycle sentinel on start cancellation, got: %v", startErr)
	}
	if got := session.ClassifyError(startErr); got != session.ErrorClassLifecycle {
		t.Fatalf("expected lifecycle class for start cancellation, got: %s", got)
	}
	if gotAttempts := factory.Attempts(); gotAttempts != 1 {
		t.Fatalf("expected cancel during backoff to stop retries after first attempt, got attempts=%d", gotAttempts)
	}
	if rt.LifecycleState() != StateDegraded {
		t.Fatalf("expected degraded after cancelled start, got: %v", rt.LifecycleState())
	}
}

func TestRuntimeReadyDialCanceledKeepsTCPDialClassOutsideStartPath(t *testing.T) {
	rt := NewRuntime(testFactory{session: &testSession{
		dialErr: errors.Join(session.ErrTCPConnectStreamFailed, context.Canceled),
	}}, RuntimeOptions{})
	if err := rt.Start(context.Background()); err != nil {
		t.Fatalf("start runtime: %v", err)
	}

	_, dialErr := rt.DialContext(context.Background(), "tcp", M.Socksaddr{
		Fqdn: "example.com",
		Port: 443,
	})
	if dialErr == nil {
		t.Fatal("expected dial error from session")
	}
	if !errors.Is(dialErr, context.Canceled) {
		t.Fatalf("expected context canceled cause from dial path, got: %v", dialErr)
	}
	if !errors.Is(dialErr, session.ErrTCPConnectStreamFailed) {
		t.Fatalf("expected tcp connect-stream sentinel from dial path, got: %v", dialErr)
	}
	if got := session.ClassifyError(dialErr); got != session.ErrorClassDial {
		t.Fatalf("expected tcp_dial class outside start-path cancellation, got: %s", got)
	}
}

func TestRuntimeDegradedDialPreservesPolicyClass(t *testing.T) {
	rt := NewRuntime(errSessionFactory{err: session.ErrPolicyFallbackDenied}, RuntimeOptions{})
	startErr := rt.Start(context.Background())
	if !errors.Is(startErr, session.ErrPolicyFallbackDenied) {
		t.Fatalf("expected policy reject from start, got: %v", startErr)
	}
	if got := session.ClassifyError(startErr); got != session.ErrorClassPolicy {
		t.Fatalf("expected start error class policy, got: %s", got)
	}
	if rt.LifecycleState() != StateDegraded {
		t.Fatalf("expected degraded state after start failure, got: %v", rt.LifecycleState())
	}

	_, dialErr := rt.DialContext(context.Background(), "tcp", M.Socksaddr{
		Fqdn: "example.com",
		Port: 443,
	})
	if dialErr == nil {
		t.Fatal("expected dial failure while runtime is degraded")
	}
	if !errors.Is(dialErr, session.ErrPolicyFallbackDenied) {
		t.Fatalf("expected dial error to retain policy cause, got: %v", dialErr)
	}
	if got := session.ClassifyError(dialErr); got != session.ErrorClassPolicy {
		t.Fatalf("expected dial error class policy, got: %s", got)
	}
	if got := session.ClassifyError(rt.LastError()); got != session.ErrorClassPolicy {
		t.Fatalf("expected runtime last error class policy, got: %s", got)
	}
}

func TestRuntimeDegradedNotReadyPreservesTransportClass(t *testing.T) {
	startCause := errors.Join(session.ErrTransportInit, errors.New("quic handshake failed"))
	rt := NewRuntime(errSessionFactory{err: startCause}, RuntimeOptions{})
	startErr := rt.Start(context.Background())
	if !errors.Is(startErr, session.ErrTransportInit) {
		t.Fatalf("expected transport init cause from start, got: %v", startErr)
	}
	if got := session.ClassifyError(startErr); got != session.ErrorClassTransport {
		t.Fatalf("expected start error class transport, got: %s", got)
	}
	if rt.LifecycleState() != StateDegraded {
		t.Fatalf("expected degraded state after transport init failure, got: %v", rt.LifecycleState())
	}

	_, dialErr := rt.DialContext(context.Background(), "tcp", M.Socksaddr{
		Fqdn: "example.com",
		Port: 443,
	})
	if dialErr == nil {
		t.Fatal("expected dial failure while runtime is degraded")
	}
	if !errors.Is(dialErr, session.ErrTransportInit) {
		t.Fatalf("expected dial error to retain transport cause, got: %v", dialErr)
	}
	if got := session.ClassifyError(dialErr); got != session.ErrorClassTransport {
		t.Fatalf("expected dial error class transport, got: %s", got)
	}

	_, listenErr := rt.ListenPacket(context.Background(), M.Socksaddr{
		Fqdn: "example.com",
		Port: 53,
	})
	if listenErr == nil {
		t.Fatal("expected listen packet failure while runtime is degraded")
	}
	if !errors.Is(listenErr, session.ErrTransportInit) {
		t.Fatalf("expected listen packet error to retain transport cause, got: %v", listenErr)
	}
	if got := session.ClassifyError(listenErr); got != session.ErrorClassTransport {
		t.Fatalf("expected listen packet error class transport, got: %s", got)
	}
	if got := session.ClassifyError(rt.LastError()); got != session.ErrorClassTransport {
		t.Fatalf("expected runtime last error class transport, got: %s", got)
	}
}

func TestRuntimeDegradedNotReadyPreservesDialClass(t *testing.T) {
	startCause := errors.Join(session.ErrTCPDial, errors.New("upstream connect timeout"))
	rt := NewRuntime(errSessionFactory{err: startCause}, RuntimeOptions{})
	startErr := rt.Start(context.Background())
	if !errors.Is(startErr, session.ErrTCPDial) {
		t.Fatalf("expected tcp dial cause from start, got: %v", startErr)
	}
	if got := session.ClassifyError(startErr); got != session.ErrorClassDial {
		t.Fatalf("expected start error class dial, got: %s", got)
	}
	if rt.LifecycleState() != StateDegraded {
		t.Fatalf("expected degraded state after dial failure, got: %v", rt.LifecycleState())
	}

	_, dialErr := rt.DialContext(context.Background(), "tcp", M.Socksaddr{
		Fqdn: "example.com",
		Port: 443,
	})
	if dialErr == nil {
		t.Fatal("expected dial failure while runtime is degraded")
	}
	if !errors.Is(dialErr, session.ErrTCPDial) {
		t.Fatalf("expected dial error to retain tcp dial cause, got: %v", dialErr)
	}
	if got := session.ClassifyError(dialErr); got != session.ErrorClassDial {
		t.Fatalf("expected dial error class dial, got: %s", got)
	}

	_, listenErr := rt.ListenPacket(context.Background(), M.Socksaddr{
		Fqdn: "example.com",
		Port: 53,
	})
	if listenErr == nil {
		t.Fatal("expected listen packet failure while runtime is degraded")
	}
	if !errors.Is(listenErr, session.ErrTCPDial) {
		t.Fatalf("expected listen packet error to retain tcp dial cause, got: %v", listenErr)
	}
	if got := session.ClassifyError(listenErr); got != session.ErrorClassDial {
		t.Fatalf("expected listen packet error class dial, got: %s", got)
	}
	if got := session.ClassifyError(rt.LastError()); got != session.ErrorClassDial {
		t.Fatalf("expected runtime last error class dial, got: %s", got)
	}
}

func TestRuntimeDegradedNotReadyPreservesCapabilityClassForTCPBoundary(t *testing.T) {
	startCause := errors.Join(session.ErrTCPPathNotImplemented, errors.New("tcp transport auto is disabled"))
	rt := NewRuntime(errSessionFactory{err: startCause}, RuntimeOptions{})
	startErr := rt.Start(context.Background())
	if !errors.Is(startErr, session.ErrTCPPathNotImplemented) {
		t.Fatalf("expected tcp path boundary cause from start, got: %v", startErr)
	}
	if got := session.ClassifyError(startErr); got != session.ErrorClassCapability {
		t.Fatalf("expected start error class capability, got: %s", got)
	}
	if rt.LifecycleState() != StateDegraded {
		t.Fatalf("expected degraded state after tcp boundary failure, got: %v", rt.LifecycleState())
	}

	_, dialErr := rt.DialContext(context.Background(), "tcp", M.Socksaddr{
		Fqdn: "example.com",
		Port: 443,
	})
	if dialErr == nil {
		t.Fatal("expected dial failure while runtime is degraded")
	}
	if !errors.Is(dialErr, session.ErrTCPPathNotImplemented) {
		t.Fatalf("expected dial error to retain tcp boundary cause, got: %v", dialErr)
	}
	if got := session.ClassifyError(dialErr); got != session.ErrorClassCapability {
		t.Fatalf("expected dial error class capability, got: %s", got)
	}

	_, listenErr := rt.ListenPacket(context.Background(), M.Socksaddr{
		Fqdn: "example.com",
		Port: 53,
	})
	if listenErr == nil {
		t.Fatal("expected listen packet failure while runtime is degraded")
	}
	if !errors.Is(listenErr, session.ErrTCPPathNotImplemented) {
		t.Fatalf("expected listen packet error to retain tcp boundary cause, got: %v", listenErr)
	}
	if got := session.ClassifyError(listenErr); got != session.ErrorClassCapability {
		t.Fatalf("expected listen packet error class capability, got: %s", got)
	}
	if got := session.ClassifyError(rt.LastError()); got != session.ErrorClassCapability {
		t.Fatalf("expected runtime last error class capability, got: %s", got)
	}
}

func TestRuntimeConnectIPStartOpensIPPlane(t *testing.T) {
	rt := NewRuntime(testFactory{session: &testSession{ip: &testIPSession{}}}, RuntimeOptions{
		DataplaneMode: option.MasqueDataplaneConnectIP,
	})
	if err := rt.Start(context.Background()); err != nil {
		t.Fatalf("start runtime: %v", err)
	}
	ip, err := rt.OpenIPSession(context.Background())
	if err != nil {
		t.Fatalf("open ip session: %v", err)
	}
	if ip == nil {
		t.Fatal("expected non-nil ip session")
	}
}

func TestRuntimeDefaultDataplaneDefersIPPlaneUntilOpen(t *testing.T) {
	ts := &testSession{ip: &testIPSession{}}
	rt := NewRuntime(testFactory{session: ts}, RuntimeOptions{
		DataplaneMode: option.MasqueDataplaneDefault,
	})
	if err := rt.Start(context.Background()); err != nil {
		t.Fatalf("start runtime: %v", err)
	}
	if ts.openIPCalls.Load() != 0 {
		t.Fatalf("default dataplane start must not open CONNECT-IP eagerly, open calls=%d", ts.openIPCalls.Load())
	}
	ip, err := rt.OpenIPSession(context.Background())
	if err != nil {
		t.Fatalf("open ip session: %v", err)
	}
	if ip == nil {
		t.Fatal("expected non-nil ip session")
	}
	if ts.openIPCalls.Load() != 1 {
		t.Fatalf("expected lazy OpenIPSession, open calls=%d", ts.openIPCalls.Load())
	}
}

func TestRuntimeOpenIPCanceledBeforeCachedIPPlaneReturn(t *testing.T) {
	ts := &testSession{ip: &testIPSession{}}
	rt := NewRuntime(testFactory{session: ts}, RuntimeOptions{
		DataplaneMode: option.MasqueDataplaneConnectIP,
	})
	if err := rt.Start(context.Background()); err != nil {
		t.Fatalf("start runtime: %v", err)
	}
	openCallsAfterStart := ts.openIPCalls.Load()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := rt.OpenIPSession(ctx)
	if err == nil {
		t.Fatal("expected error when OpenIPSession ctx is already canceled")
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got: %v", err)
	}
	// One delegated OpenIPSession on cancel so transport/masque can clear HTTP-layer fallback bookkeeping.
	if got := ts.openIPCalls.Load(); got != openCallsAfterStart+1 {
		t.Fatalf("cached-plane cancel must invoke ClientSession.OpenIPSession once for latch parity (was %d, now %d)", openCallsAfterStart, got)
	}
}

// When there is no ipPlane cache (modes other than connect_ip bootstrap), cancellation must reach
// transport/masque so http_layer_fallback latch bookkeeping matches coreSession.OpenIPSession.
func TestRuntimeOpenIPCanceledStillCallsSessionWhenNoCachedPlane(t *testing.T) {
	ts := &testSession{ip: &testIPSession{}}
	rt := NewRuntime(testFactory{session: ts}, RuntimeOptions{})
	if err := rt.Start(context.Background()); err != nil {
		t.Fatalf("start runtime: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := rt.OpenIPSession(ctx)
	if err == nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got: %v", err)
	}
	if ts.openIPCalls.Load() != 1 {
		t.Fatalf("expected one OpenIPSession call for latch parity, got %d", ts.openIPCalls.Load())
	}
}

func TestRuntimePolicyRejectClassAndObservabilityContract(t *testing.T) {
	beforeSnapshot := mcip.ObservabilitySnapshot()
	beforeReasonsRaw, ok := beforeSnapshot["connect_ip_policy_drop_icmp_reason_total"]
	if !ok {
		t.Fatal("expected connect_ip_policy_drop_icmp_reason_total in pre-snapshot")
	}
	beforeReasons, ok := beforeReasonsRaw.(map[string]uint64)
	if !ok {
		t.Fatalf("unexpected pre-snapshot reason map type: %T", beforeReasonsRaw)
	}

	rt := NewRuntime(testFactory{session: &testSession{
		ip:      &testIPSession{},
		dialErr: session.ErrPolicyFallbackDenied,
	}}, RuntimeOptions{})
	if err := rt.Start(context.Background()); err != nil {
		t.Fatalf("start runtime: %v", err)
	}
	_, dialErr := rt.DialContext(context.Background(), "tcp", M.Socksaddr{
		Fqdn: "example.com",
		Port: 443,
	})
	if !errors.Is(dialErr, session.ErrPolicyFallbackDenied) {
		t.Fatalf("expected policy reject error, got: %v", dialErr)
	}
	if got := session.ClassifyError(dialErr); got != session.ErrorClassPolicy {
		t.Fatalf("expected error class policy, got: %s", got)
	}

	afterSnapshot := mcip.ObservabilitySnapshot()
	afterReasonsRaw, ok := afterSnapshot["connect_ip_policy_drop_icmp_reason_total"]
	if !ok {
		t.Fatal("expected connect_ip_policy_drop_icmp_reason_total in post-snapshot")
	}
	afterReasons, ok := afterReasonsRaw.(map[string]uint64)
	if !ok {
		t.Fatalf("unexpected post-snapshot reason map type: %T", afterReasonsRaw)
	}
	for _, reason := range []string{"src_not_allowed", "dst_not_allowed", "proto_not_allowed"} {
		before := beforeReasons[reason]
		after := afterReasons[reason]
		if after < before {
			t.Fatalf("reason counter regressed for %s: before=%d after=%d", reason, before, after)
		}
	}
}

func TestRuntimeMalformedScopedFlowClassifiedAsCapability(t *testing.T) {
	rt := NewRuntime(T.CoreClientFactory{}, RuntimeOptions{
		Server:               "example.com",
		ServerPort:           443,
		DataplaneMode: option.MasqueDataplaneConnectIP,
		PathIP: "/.well-known/masque/ip",
		ConnectIPScopeTarget: "not-a-prefix",
	})
	startErr := rt.Start(context.Background())
	if startErr == nil {
		t.Fatal("expected start error for malformed connect_ip scope target")
	}
	if got := session.ClassifyError(startErr); got != session.ErrorClassCapability {
		t.Fatalf("expected capability error class, got: %s (err=%v)", got, startErr)
	}
	lastErr := rt.LastError()
	if lastErr == nil {
		t.Fatal("expected runtime last error to be set")
	}
	if got := session.ClassifyError(lastErr); got != session.ErrorClassCapability {
		t.Fatalf("expected capability class for runtime last error, got: %s (err=%v)", got, lastErr)
	}
	transportActual, transportResult, transportErr := T.ClassifyMalformedScopedTargetClassPair("not-a-prefix")
	if transportErr == nil {
		t.Fatal("expected malformed scoped transport helper to fail for invalid target")
	}
	if transportActual != session.ClassifyError(startErr) || transportResult != session.ClassifyError(lastErr) {
		t.Fatalf(
			"expected runtime/transport malformed scoped parity, runtime=(%s,%s) transport=(%s,%s)",
			session.ClassifyError(startErr), session.ClassifyError(lastErr), transportActual, transportResult,
		)
	}
	writeMalformedScopedLifecycleArtifactIfRequested(t, session.ClassifyError(startErr), session.ClassifyError(lastErr))
}

func TestRuntimeConnectIPOpenSessionPolicyRejectClassifiedAsPolicy(t *testing.T) {
	beforeSnapshot := mcip.ObservabilitySnapshot()
	beforeReasonsRaw, ok := beforeSnapshot["connect_ip_policy_drop_icmp_reason_total"]
	if !ok {
		t.Fatal("expected connect_ip_policy_drop_icmp_reason_total in pre-snapshot")
	}
	beforeReasons, ok := beforeReasonsRaw.(map[string]uint64)
	if !ok {
		t.Fatalf("unexpected pre-snapshot reason map type: %T", beforeReasonsRaw)
	}

	rt := NewRuntime(testFactory{session: &testSession{
		ipErr: session.ErrPolicyFallbackDenied,
	}}, RuntimeOptions{
		DataplaneMode: option.MasqueDataplaneConnectIP,
	})
	startErr := rt.Start(context.Background())
	if !errors.Is(startErr, session.ErrPolicyFallbackDenied) {
		t.Fatalf("expected policy reject from connect_ip open session, got: %v", startErr)
	}
	if got := session.ClassifyError(startErr); got != session.ErrorClassPolicy {
		t.Fatalf("expected policy class for start error, got: %s", got)
	}
	if lastErr := rt.LastError(); !errors.Is(lastErr, session.ErrPolicyFallbackDenied) {
		t.Fatalf("expected runtime last error to keep policy reject, got: %v", lastErr)
	}
	if got := session.ClassifyError(rt.LastError()); got != session.ErrorClassPolicy {
		t.Fatalf("expected policy class for runtime last error, got: %s", got)
	}

	afterSnapshot := mcip.ObservabilitySnapshot()
	afterReasonsRaw, ok := afterSnapshot["connect_ip_policy_drop_icmp_reason_total"]
	if !ok {
		t.Fatal("expected connect_ip_policy_drop_icmp_reason_total in post-snapshot")
	}
	afterReasons, ok := afterReasonsRaw.(map[string]uint64)
	if !ok {
		t.Fatalf("unexpected post-snapshot reason map type: %T", afterReasonsRaw)
	}
	for _, reason := range []string{"src_not_allowed", "dst_not_allowed", "proto_not_allowed"} {
		before := beforeReasons[reason]
		after := afterReasons[reason]
		if after < before {
			t.Fatalf("reason counter regressed for %s: before=%d after=%d", reason, before, after)
		}
	}
}

func TestRuntimeClosedDialAndListenDoNotJoinStaleLastError(t *testing.T) {
	rt := NewRuntime(errSessionFactory{err: session.ErrPolicyFallbackDenied}, RuntimeOptions{})
	startErr := rt.Start(context.Background())
	if !errors.Is(startErr, session.ErrPolicyFallbackDenied) {
		t.Fatalf("expected policy reject from start, got: %v", startErr)
	}
	if got := session.ClassifyError(startErr); got != session.ErrorClassPolicy {
		t.Fatalf("expected start error class policy, got: %s", got)
	}
	if err := rt.Close(); err != nil {
		t.Fatalf("close runtime: %v", err)
	}
	if rt.LifecycleState() != StateClosed {
		t.Fatalf("expected closed state, got: %v", rt.LifecycleState())
	}

	_, dialErr := rt.DialContext(context.Background(), "tcp", M.Socksaddr{
		Fqdn: "example.com",
		Port: 443,
	})
	if dialErr == nil {
		t.Fatal("expected dial failure on closed runtime")
	}
	if !strings.Contains(dialErr.Error(), "runtime is closed") {
		t.Fatalf("expected closed runtime dial error, got: %v", dialErr)
	}
	if !errors.Is(dialErr, session.ErrLifecycleClosed) {
		t.Fatalf("expected closed runtime dial error to include lifecycle sentinel, got: %v", dialErr)
	}
	if errors.Is(dialErr, session.ErrPolicyFallbackDenied) {
		t.Fatalf("closed dial error must not include stale policy cause, got: %v", dialErr)
	}

	_, listenErr := rt.ListenPacket(context.Background(), M.Socksaddr{
		Fqdn: "example.com",
		Port: 53,
	})
	if listenErr == nil {
		t.Fatal("expected listen packet failure on closed runtime")
	}
	if !strings.Contains(listenErr.Error(), "runtime is closed") {
		t.Fatalf("expected closed runtime listen error, got: %v", listenErr)
	}
	if !errors.Is(listenErr, session.ErrLifecycleClosed) {
		t.Fatalf("expected closed runtime listen error to include lifecycle sentinel, got: %v", listenErr)
	}
	if errors.Is(listenErr, session.ErrPolicyFallbackDenied) {
		t.Fatalf("closed listen error must not include stale policy cause, got: %v", listenErr)
	}
}

func TestRuntimeClosedDialAndListenKeepLifecycleClassAfterCapabilityFailure(t *testing.T) {
	rt := NewRuntime(errSessionFactory{err: session.ErrTCPPathNotImplemented}, RuntimeOptions{})
	startErr := rt.Start(context.Background())
	if !errors.Is(startErr, session.ErrTCPPathNotImplemented) {
		t.Fatalf("expected tcp capability reject from start, got: %v", startErr)
	}
	if got := session.ClassifyError(startErr); got != session.ErrorClassCapability {
		t.Fatalf("expected start error class capability, got: %s", got)
	}
	if err := rt.Close(); err != nil {
		t.Fatalf("close runtime: %v", err)
	}
	if rt.LifecycleState() != StateClosed {
		t.Fatalf("expected closed state, got: %v", rt.LifecycleState())
	}

	_, dialErr := rt.DialContext(context.Background(), "tcp", M.Socksaddr{
		Fqdn: "example.com",
		Port: 443,
	})
	if dialErr == nil {
		t.Fatal("expected dial failure on closed runtime")
	}
	if !strings.Contains(dialErr.Error(), "runtime is closed") {
		t.Fatalf("expected closed runtime dial error, got: %v", dialErr)
	}
	if !errors.Is(dialErr, session.ErrLifecycleClosed) {
		t.Fatalf("expected closed runtime dial error to include lifecycle sentinel, got: %v", dialErr)
	}
	if errors.Is(dialErr, session.ErrTCPPathNotImplemented) {
		t.Fatalf("closed dial error must not include stale capability cause, got: %v", dialErr)
	}
	if got := session.ClassifyError(dialErr); got != session.ErrorClassLifecycle {
		t.Fatalf("expected closed dial error class lifecycle, got: %s", got)
	}

	_, listenErr := rt.ListenPacket(context.Background(), M.Socksaddr{
		Fqdn: "example.com",
		Port: 53,
	})
	if listenErr == nil {
		t.Fatal("expected listen packet failure on closed runtime")
	}
	if !strings.Contains(listenErr.Error(), "runtime is closed") {
		t.Fatalf("expected closed runtime listen error, got: %v", listenErr)
	}
	if !errors.Is(listenErr, session.ErrLifecycleClosed) {
		t.Fatalf("expected closed runtime listen error to include lifecycle sentinel, got: %v", listenErr)
	}
	if errors.Is(listenErr, session.ErrTCPPathNotImplemented) {
		t.Fatalf("closed listen error must not include stale capability cause, got: %v", listenErr)
	}
	if got := session.ClassifyError(listenErr); got != session.ErrorClassLifecycle {
		t.Fatalf("expected closed listen error class lifecycle, got: %s", got)
	}
}

func TestRuntimeClosedOpenIPSessionKeepsLifecycleClassAfterCapabilityFailure(t *testing.T) {
	rt := NewRuntime(errSessionFactory{err: session.ErrTCPPathNotImplemented}, RuntimeOptions{})
	startErr := rt.Start(context.Background())
	if !errors.Is(startErr, session.ErrTCPPathNotImplemented) {
		t.Fatalf("expected tcp capability reject from start, got: %v", startErr)
	}
	if got := session.ClassifyError(startErr); got != session.ErrorClassCapability {
		t.Fatalf("expected start error class capability, got: %s", got)
	}
	if err := rt.Close(); err != nil {
		t.Fatalf("close runtime: %v", err)
	}
	if rt.LifecycleState() != StateClosed {
		t.Fatalf("expected closed state, got: %v", rt.LifecycleState())
	}

	ipErr := errors.New("expected open ip failure on closed runtime")
	if _, err := rt.OpenIPSession(context.Background()); err == nil {
		t.Fatal(ipErr)
	} else {
		if !strings.Contains(err.Error(), "runtime is closed") {
			t.Fatalf("expected closed runtime open ip error, got: %v", err)
		}
		if !errors.Is(err, session.ErrLifecycleClosed) {
			t.Fatalf("expected closed runtime open ip error to include lifecycle sentinel, got: %v", err)
		}
		if errors.Is(err, session.ErrTCPPathNotImplemented) {
			t.Fatalf("closed open ip error must not include stale capability cause, got: %v", err)
		}
		if got := session.ClassifyError(err); got != session.ErrorClassLifecycle {
			t.Fatalf("expected closed open ip error class lifecycle, got: %s", got)
		}
	}
}

func TestRuntimeClosedStartKeepsLifecycleClassAfterCapabilityFailure(t *testing.T) {
	rt := NewRuntime(errSessionFactory{err: session.ErrTCPPathNotImplemented}, RuntimeOptions{})
	startErr := rt.Start(context.Background())
	if !errors.Is(startErr, session.ErrTCPPathNotImplemented) {
		t.Fatalf("expected tcp capability reject from start, got: %v", startErr)
	}
	if got := session.ClassifyError(startErr); got != session.ErrorClassCapability {
		t.Fatalf("expected start error class capability, got: %s", got)
	}
	if err := rt.Close(); err != nil {
		t.Fatalf("close runtime: %v", err)
	}
	if rt.LifecycleState() != StateClosed {
		t.Fatalf("expected closed state, got: %v", rt.LifecycleState())
	}

	restartErr := rt.Start(context.Background())
	if restartErr == nil {
		t.Fatal("expected start failure on closed runtime")
	}
	if !strings.Contains(restartErr.Error(), "runtime is closed") {
		t.Fatalf("expected closed runtime start error, got: %v", restartErr)
	}
	if !errors.Is(restartErr, session.ErrLifecycleClosed) {
		t.Fatalf("expected closed runtime start error to include lifecycle sentinel, got: %v", restartErr)
	}
	if errors.Is(restartErr, session.ErrTCPPathNotImplemented) {
		t.Fatalf("closed start error must not include stale capability cause, got: %v", restartErr)
	}
	if got := session.ClassifyError(restartErr); got != session.ErrorClassLifecycle {
		t.Fatalf("expected closed start error class lifecycle, got: %s", got)
	}
}

func TestRuntimePeerClosedNotReadyClassifiedAsLifecycle(t *testing.T) {
	startCause := errors.Join(session.ErrLifecycleClosed, net.ErrClosed)
	rt := NewRuntime(errSessionFactory{err: startCause}, RuntimeOptions{})
	startErr := rt.Start(context.Background())
	if !errors.Is(startErr, net.ErrClosed) {
		t.Fatalf("expected start error to preserve net.ErrClosed cause, got: %v", startErr)
	}
	if got := session.ClassifyError(startErr); got != session.ErrorClassLifecycle {
		t.Fatalf("expected start error class lifecycle, got: %s", got)
	}
	if rt.LifecycleState() != StateDegraded {
		t.Fatalf("expected degraded state after peer-close start failure, got: %v", rt.LifecycleState())
	}

	_, dialErr := rt.DialContext(context.Background(), "tcp", M.Socksaddr{
		Fqdn: "example.com",
		Port: 443,
	})
	if dialErr == nil {
		t.Fatal("expected dial failure while runtime is degraded by peer close")
	}
	if !errors.Is(dialErr, net.ErrClosed) {
		t.Fatalf("expected dial error to preserve net.ErrClosed cause, got: %v", dialErr)
	}
	if got := session.ClassifyError(dialErr); got != session.ErrorClassLifecycle {
		t.Fatalf("expected dial error class lifecycle, got: %s", got)
	}

	_, listenErr := rt.ListenPacket(context.Background(), M.Socksaddr{
		Fqdn: "example.com",
		Port: 53,
	})
	if listenErr == nil {
		t.Fatal("expected listen packet failure while runtime is degraded by peer close")
	}
	if !errors.Is(listenErr, net.ErrClosed) {
		t.Fatalf("expected listen error to preserve net.ErrClosed cause, got: %v", listenErr)
	}
	if got := session.ClassifyError(listenErr); got != session.ErrorClassLifecycle {
		t.Fatalf("expected listen error class lifecycle, got: %s", got)
	}
	if got := session.ClassifyError(rt.LastError()); got != session.ErrorClassLifecycle {
		t.Fatalf("expected runtime last error class lifecycle, got: %s", got)
	}
}

func TestRuntimePeerRemoteCloseNotReadyClassifiedAsLifecycle(t *testing.T) {
	remoteClose := &connectip.CloseError{Remote: true}
	startCause := errors.Join(session.ErrLifecycleClosed, remoteClose)
	rt := NewRuntime(errSessionFactory{err: startCause}, RuntimeOptions{})
	startErr := rt.Start(context.Background())
	if !errors.Is(startErr, net.ErrClosed) {
		t.Fatalf("expected start error to preserve net.ErrClosed via remote close, got: %v", startErr)
	}
	if got := session.ClassifyError(startErr); got != session.ErrorClassLifecycle {
		t.Fatalf("expected start error class lifecycle for remote close, got: %s", got)
	}
	if rt.LifecycleState() != StateDegraded {
		t.Fatalf("expected degraded state after remote peer-close start failure, got: %v", rt.LifecycleState())
	}

	_, dialErr := rt.DialContext(context.Background(), "tcp", M.Socksaddr{
		Fqdn: "example.com",
		Port: 443,
	})
	if dialErr == nil {
		t.Fatal("expected dial failure while runtime is degraded by remote peer close")
	}
	if !errors.Is(dialErr, net.ErrClosed) {
		t.Fatalf("expected dial error to preserve net.ErrClosed via remote close, got: %v", dialErr)
	}
	if got := session.ClassifyError(dialErr); got != session.ErrorClassLifecycle {
		t.Fatalf("expected dial error class lifecycle for remote close, got: %s", got)
	}

	_, listenErr := rt.ListenPacket(context.Background(), M.Socksaddr{
		Fqdn: "example.com",
		Port: 53,
	})
	if listenErr == nil {
		t.Fatal("expected listen packet failure while runtime is degraded by remote peer close")
	}
	if !errors.Is(listenErr, net.ErrClosed) {
		t.Fatalf("expected listen error to preserve net.ErrClosed via remote close, got: %v", listenErr)
	}
	if got := session.ClassifyError(listenErr); got != session.ErrorClassLifecycle {
		t.Fatalf("expected listen error class lifecycle for remote close, got: %s", got)
	}
	if got := session.ClassifyError(rt.LastError()); got != session.ErrorClassLifecycle {
		t.Fatalf("expected runtime last error class lifecycle for remote close, got: %s", got)
	}

	writePeerAbortLifecycleArtifactIfRequested(t, session.ClassifyError(startErr), session.ClassifyError(dialErr))
}

func writePeerAbortLifecycleArtifactIfRequested(t *testing.T, actualClass, resultClass session.ErrorClass) {
	t.Helper()

	artifactPath := os.Getenv("MASQUE_PEER_ABORT_ARTIFACT_PATH")
	if artifactPath == "" {
		return
	}
	ok := actualClass == session.ErrorClassLifecycle && resultClass == session.ErrorClassLifecycle
	artifact := map[string]any{
		"ok":                     ok,
		"actual_error_class":     string(actualClass),
		"result_error_class":     string(resultClass),
		"error_class_consistent": ok,
		"error_source":           "runtime",
	}
	raw, err := json.MarshalIndent(artifact, "", "  ")
	if err != nil {
		t.Fatalf("marshal peer-abort lifecycle artifact: %v", err)
	}
	if err := os.WriteFile(artifactPath, raw, 0o644); err != nil {
		t.Fatalf("write peer-abort lifecycle artifact: %v", err)
	}
}

func writeMalformedScopedLifecycleArtifactIfRequested(t *testing.T, actualClass, resultClass session.ErrorClass) {
	t.Helper()

	artifactPath := os.Getenv("MASQUE_MALFORMED_SCOPED_ARTIFACT_PATH")
	if artifactPath == "" {
		return
	}
	artifact := session.BuildScopedErrorArtifact(actualClass, resultClass, "runtime")
	raw, err := json.MarshalIndent(artifact, "", "  ")
	if err != nil {
		t.Fatalf("marshal malformed-scoped artifact: %v", err)
	}
	if err := os.WriteFile(artifactPath, raw, 0o644); err != nil {
		t.Fatalf("write malformed-scoped artifact: %v", err)
	}
}
