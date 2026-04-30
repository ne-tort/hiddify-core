package masque

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"
)

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
	if !ipSession.Capabilities().ConnectTCP {
		t.Fatal("expected connect_ip session to advertise ConnectTCP")
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
}

func TestSelectTCPPath(t *testing.T) {
	if selectTCPPath(ClientOptions{TCPTransport: option.MasqueTCPTransportConnectStream}) != TCPPathConnectStream {
		t.Fatal("expected connect_stream path")
	}
	if selectTCPPath(ClientOptions{TCPTransport: option.MasqueTCPTransportConnectIP}) != TCPPathConnectIP {
		t.Fatal("expected connect_ip path")
	}
	if selectTCPPath(ClientOptions{TCPTransport: option.MasqueTCPTransportAuto}) != TCPPathAuto {
		t.Fatal("expected auto path")
	}
}

func TestTCPOverIPDialerReturnsTypedStackInitError(t *testing.T) {
	dialer := newTCPOverIPDialer(unavailableTCPNetstackFactory{}, fakeIPPacketSession{})
	_, err := dialer.DialContext(context.Background(), M.Socksaddr{Fqdn: "example.com", Port: 443})
	if err == nil {
		t.Fatal("expected typed stack init error")
	}
	if !errors.Is(err, ErrTCPStackInit) {
		t.Fatalf("expected tcp stack init error, got: %v", err)
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

func TestTCPOverIPDialerRetryBoundaryThreeAttempts(t *testing.T) {
	stack := &fakeTCPNetstack{
		dialFn: func(_ context.Context, _ M.Socksaddr, _ int) (net.Conn, error) {
			return nil, errors.New("temporary failure")
		},
	}
	dialer := newTCPOverIPDialer(fakeTCPNetstackFactory{stack: stack}, fakeIPPacketSession{})
	_, err := dialer.DialContext(context.Background(), M.Socksaddr{Fqdn: "example.com", Port: 443})
	if err == nil {
		t.Fatal("expected tcp-over-ip dial to fail after retries")
	}
	if !errors.Is(err, ErrTCPDial) {
		t.Fatalf("expected typed tcp dial error, got: %v", err)
	}
	if stack.attempts != 3 {
		t.Fatalf("expected exactly 3 dial attempts, got: %d", stack.attempts)
	}
}

func TestTCPOverIPDialerCancelledContextStopsRetryLoop(t *testing.T) {
	stack := &fakeTCPNetstack{
		dialFn: func(ctx context.Context, _ M.Socksaddr, _ int) (net.Conn, error) {
			return nil, context.Cause(ctx)
		},
	}
	dialer := newTCPOverIPDialer(fakeTCPNetstackFactory{stack: stack}, fakeIPPacketSession{})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := dialer.DialContext(ctx, M.Socksaddr{Fqdn: "example.com", Port: 443})
	if err == nil {
		t.Fatal("expected error for cancelled context")
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected cancelled context in error chain, got: %v", err)
	}
	if stack.attempts != 1 {
		t.Fatalf("expected single attempt when context already cancelled, got: %d", stack.attempts)
	}
}

func TestTCPOverIPDialerLifecycleCloseThenDial(t *testing.T) {
	dialer := newTCPOverIPDialer(fakeTCPNetstackFactory{
		stack: &fakeTCPNetstack{},
	}, fakeIPPacketSession{})
	if err := dialer.Close(); err != nil {
		t.Fatalf("close dialer: %v", err)
	}
	_, err := dialer.DialContext(context.Background(), M.Socksaddr{Fqdn: "example.com", Port: 443})
	if !errors.Is(err, ErrLifecycleClosed) {
		t.Fatalf("expected lifecycle closed error, got: %v", err)
	}
}

func TestConnectIPClassifiesAsCapabilityError(t *testing.T) {
	err := classifyTCPNotImplemented(TCPPathConnectIP)
	if !errors.Is(err, ErrTCPOverConnectIP) {
		t.Fatalf("expected connect_ip path marker, got: %v", err)
	}
	if ClassifyError(err) != ErrorClassCapability {
		t.Fatalf("expected capability class, got: %s", ClassifyError(err))
	}
}

func TestCapabilityContractFallbackByTCPModeForConnectIP(t *testing.T) {
	allowed := fallbackAllowedForError(ClientOptions{
		FallbackPolicy: option.MasqueFallbackPolicyDirectExplicit,
		TCPMode:        option.MasqueTCPModeMasqueOrDirect,
	}, "tcp", ErrTCPOverConnectIP)
	if !allowed {
		t.Fatal("expected masque_or_direct to allow fallback on connect_ip capability error")
	}

	denied := fallbackAllowedForError(ClientOptions{
		FallbackPolicy: option.MasqueFallbackPolicyDirectExplicit,
		TCPMode:        option.MasqueTCPModeStrictMasque,
	}, "tcp", ErrTCPOverConnectIP)
	if denied {
		t.Fatal("expected strict_masque to deny fallback on connect_ip capability error")
	}
}

func TestFallbackAllowedForErrorClassificationMatrix(t *testing.T) {
	testCases := []struct {
		name    string
		options ClientOptions
		network string
		err     error
		want    bool
	}{
		{
			name: "masque_or_direct tcp capability",
			options: ClientOptions{
				FallbackPolicy: option.MasqueFallbackPolicyDirectExplicit,
				TCPMode:        option.MasqueTCPModeMasqueOrDirect,
			},
			network: "tcp",
			err:     ErrTCPOverConnectIP,
			want:    true,
		},
		{
			name: "masque_or_direct tcp dial",
			options: ClientOptions{
				FallbackPolicy: option.MasqueFallbackPolicyDirectExplicit,
				TCPMode:        option.MasqueTCPModeMasqueOrDirect,
			},
			network: "tcp6",
			err:     ErrTCPDial,
			want:    true,
		},
		{
			name: "masque_or_direct tcp stack init",
			options: ClientOptions{
				FallbackPolicy: option.MasqueFallbackPolicyDirectExplicit,
				TCPMode:        option.MasqueTCPModeMasqueOrDirect,
			},
			network: "tcp4",
			err:     ErrTCPStackInit,
			want:    true,
		},
		{
			name: "strict mode denies capability fallback",
			options: ClientOptions{
				FallbackPolicy: option.MasqueFallbackPolicyDirectExplicit,
				TCPMode:        option.MasqueTCPModeStrictMasque,
			},
			network: "tcp",
			err:     ErrTCPOverConnectIP,
			want:    false,
		},
		{
			name: "non explicit policy denies fallback",
			options: ClientOptions{
				FallbackPolicy: option.MasqueFallbackPolicyStrict,
				TCPMode:        option.MasqueTCPModeMasqueOrDirect,
			},
			network: "tcp",
			err:     ErrTCPOverConnectIP,
			want:    false,
		},
		{
			name: "udp network denies tcp fallback",
			options: ClientOptions{
				FallbackPolicy: option.MasqueFallbackPolicyDirectExplicit,
				TCPMode:        option.MasqueTCPModeMasqueOrDirect,
			},
			network: "udp",
			err:     ErrTCPDial,
			want:    false,
		},
		{
			name: "auth class does not fallback",
			options: ClientOptions{
				FallbackPolicy: option.MasqueFallbackPolicyDirectExplicit,
				TCPMode:        option.MasqueTCPModeMasqueOrDirect,
			},
			network: "tcp",
			err:     ErrAuthFailed,
			want:    false,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got := fallbackAllowedForError(tc.options, tc.network, tc.err)
			if got != tc.want {
				t.Fatalf("fallbackAllowedForError=%v want=%v", got, tc.want)
			}
		})
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

func TestTCPOverIPDialerCancelDuringBackoffStopsRetries(t *testing.T) {
	stack := &fakeTCPNetstack{
		dialFn: func(ctx context.Context, _ M.Socksaddr, attempt int) (net.Conn, error) {
			if attempt == 1 {
				cancel, ok := ctx.Value(testCancelKey{}).(context.CancelFunc)
				if ok && cancel != nil {
					cancel()
				}
			}
			return nil, errors.New("temporary failure")
		},
	}
	dialer := newTCPOverIPDialer(fakeTCPNetstackFactory{stack: stack}, fakeIPPacketSession{})
	ctx, cancel := context.WithCancel(context.Background())
	ctx = context.WithValue(ctx, testCancelKey{}, context.CancelFunc(cancel))
	_, err := dialer.DialContext(ctx, M.Socksaddr{Fqdn: "example.com", Port: 443})
	if err == nil {
		t.Fatal("expected context cancellation during retry backoff")
	}
	if !errors.Is(err, ErrTCPDial) {
		t.Fatalf("expected retry loop to return typed dial failure, got: %v", err)
	}
	if stack.attempts != 1 {
		t.Fatalf("expected retry loop to stop after first attempt, got: %d", stack.attempts)
	}
}

func TestTCPOverIPDialerStackInitFailureCanRecoverOnNextDial(t *testing.T) {
	factory := &flakyTCPNetstackFactory{}
	dialer := newTCPOverIPDialer(factory, fakeIPPacketSession{})
	_, firstErr := dialer.DialContext(context.Background(), M.Socksaddr{Fqdn: "example.com", Port: 443})
	if firstErr == nil || !errors.Is(firstErr, ErrTCPStackInit) {
		t.Fatalf("expected first call to fail with stack init error, got: %v", firstErr)
	}
	conn, secondErr := dialer.DialContext(context.Background(), M.Socksaddr{Fqdn: "example.com", Port: 443})
	if secondErr != nil {
		t.Fatalf("expected second call to recover, got: %v", secondErr)
	}
	if conn == nil {
		t.Fatal("expected non-nil connection on recovery dial")
	}
	_ = conn.Close()
	if factory.calls != 2 {
		t.Fatalf("expected factory to be called twice, got: %d", factory.calls)
	}
}

func TestTCPOverIPDialerCloseIsIdempotent(t *testing.T) {
	dialer := newTCPOverIPDialer(fakeTCPNetstackFactory{stack: &fakeTCPNetstack{}}, fakeIPPacketSession{})
	if err := dialer.Close(); err != nil {
		t.Fatalf("first close failed: %v", err)
	}
	if err := dialer.Close(); err != nil {
		t.Fatalf("second close failed: %v", err)
	}
}

func TestTCPOverIPDialerAppliesDefaultTimeoutWithoutDeadline(t *testing.T) {
	prev := defaultTCPOverIPDialTimeout
	defaultTCPOverIPDialTimeout = 120 * time.Millisecond
	defer func() {
		defaultTCPOverIPDialTimeout = prev
	}()

	stack := &fakeTCPNetstack{
		dialFn: func(ctx context.Context, _ M.Socksaddr, _ int) (net.Conn, error) {
			<-ctx.Done()
			return nil, ctx.Err()
		},
	}
	dialer := newTCPOverIPDialer(fakeTCPNetstackFactory{stack: stack}, fakeIPPacketSession{})
	start := time.Now()
	_, err := dialer.DialContext(context.Background(), M.Socksaddr{Fqdn: "example.com", Port: 443})
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("expected timeout error")
	}
	if elapsed > time.Second {
		t.Fatalf("default timeout budget was not applied, elapsed=%s", elapsed)
	}
	if !errors.Is(err, context.DeadlineExceeded) && !errors.Is(err, context.Canceled) {
		t.Fatalf("expected timeout/cancel cause in chain, got: %v", err)
	}
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

type fakeIPPacketSession struct{}

func (f fakeIPPacketSession) ReadPacket(buffer []byte) (int, error) { return 0, nil }
func (f fakeIPPacketSession) WritePacket(buffer []byte) error       { return nil }
func (f fakeIPPacketSession) Close() error                          { return nil }

type fakeDeadlineReader struct{}

func (f *fakeDeadlineReader) Read(_ []byte) (int, error) { return 0, io.EOF }

type fakeWriter struct{}

func (f *fakeWriter) Write(p []byte) (int, error) { return len(p), nil }
func (f *fakeWriter) Close() error                { return nil }

type fakeTCPNetstackFactory struct {
	stack TCPNetstack
}

func (f fakeTCPNetstackFactory) New(_ context.Context, _ IPPacketSession) (TCPNetstack, error) {
	if f.stack == nil {
		return nil, errors.New("stack is nil")
	}
	return f.stack, nil
}

type fakeTCPNetstack struct {
	attempts int
	dialFn   func(ctx context.Context, destination M.Socksaddr, attempt int) (net.Conn, error)
}

func (s *fakeTCPNetstack) DialContext(ctx context.Context, destination M.Socksaddr) (net.Conn, error) {
	s.attempts++
	if s.dialFn != nil {
		return s.dialFn(ctx, destination, s.attempts)
	}
	return nil, errors.New("dial failed")
}

func (s *fakeTCPNetstack) Close() error { return nil }

type flakyTCPNetstackFactory struct {
	calls int
}

func (f *flakyTCPNetstackFactory) New(_ context.Context, _ IPPacketSession) (TCPNetstack, error) {
	f.calls++
	if f.calls == 1 {
		return nil, errors.New("stack bootstrap failed")
	}
	return &fakeTCPNetstack{
		dialFn: func(_ context.Context, _ M.Socksaddr, _ int) (net.Conn, error) {
			c1, c2 := net.Pipe()
			_ = c2.Close()
			return c1, nil
		},
	}, nil
}

type testCancelKey struct{}

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
