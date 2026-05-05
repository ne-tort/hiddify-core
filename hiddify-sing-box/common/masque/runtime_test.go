package masque

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"strings"
	"testing"

	connectip "github.com/quic-go/connect-ip-go"
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
	ip      T.IPPacketSession
	dialErr error
	ipErr   error
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

type errSessionFactory struct {
	err error
}

func (f errSessionFactory) NewSession(ctx context.Context, options T.ClientOptions) (T.ClientSession, error) {
	return nil, f.err
}

// cancelProbeFactory fails NewSession when ctx is already cancelled (models transport respecting router/box ctx).
type cancelProbeFactory struct{}

func (cancelProbeFactory) NewSession(ctx context.Context, options T.ClientOptions) (T.ClientSession, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return &testSession{}, nil
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
	if got := T.ClassifyError(startErr); got != T.ErrorClassLifecycle {
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

func TestRuntimeDegradedDialPreservesPolicyClass(t *testing.T) {
	rt := NewRuntime(errSessionFactory{err: T.ErrPolicyFallbackDenied}, RuntimeOptions{})
	startErr := rt.Start(context.Background())
	if !errors.Is(startErr, T.ErrPolicyFallbackDenied) {
		t.Fatalf("expected policy reject from start, got: %v", startErr)
	}
	if got := T.ClassifyError(startErr); got != T.ErrorClassPolicy {
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
	if !errors.Is(dialErr, T.ErrPolicyFallbackDenied) {
		t.Fatalf("expected dial error to retain policy cause, got: %v", dialErr)
	}
	if got := T.ClassifyError(dialErr); got != T.ErrorClassPolicy {
		t.Fatalf("expected dial error class policy, got: %s", got)
	}
	if got := T.ClassifyError(rt.LastError()); got != T.ErrorClassPolicy {
		t.Fatalf("expected runtime last error class policy, got: %s", got)
	}
}

func TestRuntimeDegradedNotReadyPreservesTransportClass(t *testing.T) {
	startCause := errors.Join(T.ErrTransportInit, errors.New("quic handshake failed"))
	rt := NewRuntime(errSessionFactory{err: startCause}, RuntimeOptions{})
	startErr := rt.Start(context.Background())
	if !errors.Is(startErr, T.ErrTransportInit) {
		t.Fatalf("expected transport init cause from start, got: %v", startErr)
	}
	if got := T.ClassifyError(startErr); got != T.ErrorClassTransport {
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
	if !errors.Is(dialErr, T.ErrTransportInit) {
		t.Fatalf("expected dial error to retain transport cause, got: %v", dialErr)
	}
	if got := T.ClassifyError(dialErr); got != T.ErrorClassTransport {
		t.Fatalf("expected dial error class transport, got: %s", got)
	}

	_, listenErr := rt.ListenPacket(context.Background(), M.Socksaddr{
		Fqdn: "example.com",
		Port: 53,
	})
	if listenErr == nil {
		t.Fatal("expected listen packet failure while runtime is degraded")
	}
	if !errors.Is(listenErr, T.ErrTransportInit) {
		t.Fatalf("expected listen packet error to retain transport cause, got: %v", listenErr)
	}
	if got := T.ClassifyError(listenErr); got != T.ErrorClassTransport {
		t.Fatalf("expected listen packet error class transport, got: %s", got)
	}
	if got := T.ClassifyError(rt.LastError()); got != T.ErrorClassTransport {
		t.Fatalf("expected runtime last error class transport, got: %s", got)
	}
}

func TestRuntimeDegradedNotReadyPreservesDialClass(t *testing.T) {
	startCause := errors.Join(T.ErrTCPDial, errors.New("upstream connect timeout"))
	rt := NewRuntime(errSessionFactory{err: startCause}, RuntimeOptions{})
	startErr := rt.Start(context.Background())
	if !errors.Is(startErr, T.ErrTCPDial) {
		t.Fatalf("expected tcp dial cause from start, got: %v", startErr)
	}
	if got := T.ClassifyError(startErr); got != T.ErrorClassDial {
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
	if !errors.Is(dialErr, T.ErrTCPDial) {
		t.Fatalf("expected dial error to retain tcp dial cause, got: %v", dialErr)
	}
	if got := T.ClassifyError(dialErr); got != T.ErrorClassDial {
		t.Fatalf("expected dial error class dial, got: %s", got)
	}

	_, listenErr := rt.ListenPacket(context.Background(), M.Socksaddr{
		Fqdn: "example.com",
		Port: 53,
	})
	if listenErr == nil {
		t.Fatal("expected listen packet failure while runtime is degraded")
	}
	if !errors.Is(listenErr, T.ErrTCPDial) {
		t.Fatalf("expected listen packet error to retain tcp dial cause, got: %v", listenErr)
	}
	if got := T.ClassifyError(listenErr); got != T.ErrorClassDial {
		t.Fatalf("expected listen packet error class dial, got: %s", got)
	}
	if got := T.ClassifyError(rt.LastError()); got != T.ErrorClassDial {
		t.Fatalf("expected runtime last error class dial, got: %s", got)
	}
}

func TestRuntimeConnectIPStartOpensIPPlane(t *testing.T) {
	rt := NewRuntime(testFactory{session: &testSession{ip: &testIPSession{}}}, RuntimeOptions{
		TransportMode: "connect_ip",
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

func TestRuntimePolicyRejectClassAndObservabilityContract(t *testing.T) {
	beforeSnapshot := T.ConnectIPObservabilitySnapshot()
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
		dialErr: T.ErrPolicyFallbackDenied,
	}}, RuntimeOptions{})
	if err := rt.Start(context.Background()); err != nil {
		t.Fatalf("start runtime: %v", err)
	}
	_, dialErr := rt.DialContext(context.Background(), "tcp", M.Socksaddr{
		Fqdn: "example.com",
		Port: 443,
	})
	if !errors.Is(dialErr, T.ErrPolicyFallbackDenied) {
		t.Fatalf("expected policy reject error, got: %v", dialErr)
	}
	if got := T.ClassifyError(dialErr); got != T.ErrorClassPolicy {
		t.Fatalf("expected error class policy, got: %s", got)
	}

	afterSnapshot := T.ConnectIPObservabilitySnapshot()
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
		TransportMode:        "connect_ip",
		TemplateIP:           "https://example.com/masque/ip/{target}/{ipproto}",
		ConnectIPScopeTarget: "not-a-prefix",
	})
	startErr := rt.Start(context.Background())
	if startErr == nil {
		t.Fatal("expected start error for malformed connect_ip scope target")
	}
	if got := T.ClassifyError(startErr); got != T.ErrorClassCapability {
		t.Fatalf("expected capability error class, got: %s (err=%v)", got, startErr)
	}
	lastErr := rt.LastError()
	if lastErr == nil {
		t.Fatal("expected runtime last error to be set")
	}
	if got := T.ClassifyError(lastErr); got != T.ErrorClassCapability {
		t.Fatalf("expected capability class for runtime last error, got: %s (err=%v)", got, lastErr)
	}
	transportActual, transportResult, transportErr := T.ClassifyMalformedScopedTargetClassPair("not-a-prefix")
	if transportErr == nil {
		t.Fatal("expected malformed scoped transport helper to fail for invalid target")
	}
	if transportActual != T.ClassifyError(startErr) || transportResult != T.ClassifyError(lastErr) {
		t.Fatalf(
			"expected runtime/transport malformed scoped parity, runtime=(%s,%s) transport=(%s,%s)",
			T.ClassifyError(startErr), T.ClassifyError(lastErr), transportActual, transportResult,
		)
	}
	writeMalformedScopedLifecycleArtifactIfRequested(t, T.ClassifyError(startErr), T.ClassifyError(lastErr))
}

func TestRuntimeConnectIPOpenSessionPolicyRejectClassifiedAsPolicy(t *testing.T) {
	beforeSnapshot := T.ConnectIPObservabilitySnapshot()
	beforeReasonsRaw, ok := beforeSnapshot["connect_ip_policy_drop_icmp_reason_total"]
	if !ok {
		t.Fatal("expected connect_ip_policy_drop_icmp_reason_total in pre-snapshot")
	}
	beforeReasons, ok := beforeReasonsRaw.(map[string]uint64)
	if !ok {
		t.Fatalf("unexpected pre-snapshot reason map type: %T", beforeReasonsRaw)
	}

	rt := NewRuntime(testFactory{session: &testSession{
		ipErr: T.ErrPolicyFallbackDenied,
	}}, RuntimeOptions{
		TransportMode: transportModeConnectIP,
	})
	startErr := rt.Start(context.Background())
	if !errors.Is(startErr, T.ErrPolicyFallbackDenied) {
		t.Fatalf("expected policy reject from connect_ip open session, got: %v", startErr)
	}
	if got := T.ClassifyError(startErr); got != T.ErrorClassPolicy {
		t.Fatalf("expected policy class for start error, got: %s", got)
	}
	if lastErr := rt.LastError(); !errors.Is(lastErr, T.ErrPolicyFallbackDenied) {
		t.Fatalf("expected runtime last error to keep policy reject, got: %v", lastErr)
	}
	if got := T.ClassifyError(rt.LastError()); got != T.ErrorClassPolicy {
		t.Fatalf("expected policy class for runtime last error, got: %s", got)
	}

	afterSnapshot := T.ConnectIPObservabilitySnapshot()
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
	rt := NewRuntime(errSessionFactory{err: T.ErrPolicyFallbackDenied}, RuntimeOptions{})
	startErr := rt.Start(context.Background())
	if !errors.Is(startErr, T.ErrPolicyFallbackDenied) {
		t.Fatalf("expected policy reject from start, got: %v", startErr)
	}
	if got := T.ClassifyError(startErr); got != T.ErrorClassPolicy {
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
	if errors.Is(dialErr, T.ErrPolicyFallbackDenied) {
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
	if errors.Is(listenErr, T.ErrPolicyFallbackDenied) {
		t.Fatalf("closed listen error must not include stale policy cause, got: %v", listenErr)
	}
}

func TestRuntimePeerClosedNotReadyClassifiedAsLifecycle(t *testing.T) {
	startCause := errors.Join(T.ErrLifecycleClosed, net.ErrClosed)
	rt := NewRuntime(errSessionFactory{err: startCause}, RuntimeOptions{})
	startErr := rt.Start(context.Background())
	if !errors.Is(startErr, net.ErrClosed) {
		t.Fatalf("expected start error to preserve net.ErrClosed cause, got: %v", startErr)
	}
	if got := T.ClassifyError(startErr); got != T.ErrorClassLifecycle {
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
	if got := T.ClassifyError(dialErr); got != T.ErrorClassLifecycle {
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
	if got := T.ClassifyError(listenErr); got != T.ErrorClassLifecycle {
		t.Fatalf("expected listen error class lifecycle, got: %s", got)
	}
	if got := T.ClassifyError(rt.LastError()); got != T.ErrorClassLifecycle {
		t.Fatalf("expected runtime last error class lifecycle, got: %s", got)
	}
}

func TestRuntimePeerRemoteCloseNotReadyClassifiedAsLifecycle(t *testing.T) {
	remoteClose := &connectip.CloseError{Remote: true}
	startCause := errors.Join(T.ErrLifecycleClosed, remoteClose)
	rt := NewRuntime(errSessionFactory{err: startCause}, RuntimeOptions{})
	startErr := rt.Start(context.Background())
	if !errors.Is(startErr, net.ErrClosed) {
		t.Fatalf("expected start error to preserve net.ErrClosed via remote close, got: %v", startErr)
	}
	if got := T.ClassifyError(startErr); got != T.ErrorClassLifecycle {
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
	if got := T.ClassifyError(dialErr); got != T.ErrorClassLifecycle {
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
	if got := T.ClassifyError(listenErr); got != T.ErrorClassLifecycle {
		t.Fatalf("expected listen error class lifecycle for remote close, got: %s", got)
	}
	if got := T.ClassifyError(rt.LastError()); got != T.ErrorClassLifecycle {
		t.Fatalf("expected runtime last error class lifecycle for remote close, got: %s", got)
	}

	writePeerAbortLifecycleArtifactIfRequested(t, T.ClassifyError(startErr), T.ClassifyError(dialErr))
}

func writePeerAbortLifecycleArtifactIfRequested(t *testing.T, actualClass, resultClass T.ErrorClass) {
	t.Helper()

	artifactPath := os.Getenv("MASQUE_PEER_ABORT_ARTIFACT_PATH")
	if artifactPath == "" {
		return
	}
	ok := actualClass == T.ErrorClassLifecycle && resultClass == T.ErrorClassLifecycle
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

func writeMalformedScopedLifecycleArtifactIfRequested(t *testing.T, actualClass, resultClass T.ErrorClass) {
	t.Helper()

	artifactPath := os.Getenv("MASQUE_MALFORMED_SCOPED_ARTIFACT_PATH")
	if artifactPath == "" {
		return
	}
	artifact := T.BuildScopedErrorArtifact(actualClass, resultClass, "runtime")
	raw, err := json.MarshalIndent(artifact, "", "  ")
	if err != nil {
		t.Fatalf("marshal malformed-scoped artifact: %v", err)
	}
	if err := os.WriteFile(artifactPath, raw, 0o644); err != nil {
		t.Fatalf("write malformed-scoped artifact: %v", err)
	}
}

