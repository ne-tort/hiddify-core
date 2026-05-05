package masque

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"testing"
	"time"

	connectip "github.com/quic-go/connect-ip-go"
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
	if !isRetryableConnectIPError(errors.New("timeout: no recent network activity")) {
		t.Fatal("expected timeout/no recent network activity to be retryable")
	}
	if !isRetryableConnectIPError(errors.New("write failed: use of closed network connection")) {
		t.Fatal("expected closed network connection to be retryable")
	}
	if isRetryableConnectIPError(errors.New("authorization failed")) {
		t.Fatal("expected auth failures to be non-retryable")
	}
}

func TestConnectIPPacketSessionDatagramCeiling(t *testing.T) {
	session := &connectIPPacketSession{datagramCeiling: 1280}
	_, err := session.WritePacket(make([]byte, 1400))
	if err == nil {
		t.Fatal("expected datagram ceiling error")
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
	session := &coreSession{
		options: ClientOptions{
			Server:      "masque.local",
			ServerPort:  443,
			TemplateTCP: "https://masque.local/masque/tcp/{target_host}/{target_port}",
		},
		tcpRoundTripper: roundTripperFunc(func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusBadGateway,
				Body:       io.NopCloser(bytes.NewReader(nil)),
			}, nil
		}),
	}
	_, err := session.dialTCPStream(context.Background(), M.ParseSocksaddrHostPort("example.com", 443))
	if !errors.Is(err, ErrTCPConnectStreamFailed) {
		t.Fatalf("expected ErrTCPConnectStreamFailed for non-auth non-2xx status, got: %v", err)
	}
	if got := ClassifyError(err); got != ErrorClassDial {
		t.Fatalf("expected dial class for non-auth non-2xx status, got: %s", got)
	}
}

func TestDialTCPStreamRetryableRoundTripErrorsKeepDialClassAndBudget(t *testing.T) {
	retryableErrors := []string{
		"timeout while connecting",
		"no recent network activity",
		"idle timeout reached",
		"application error 0x100",
	}
	for _, errorText := range retryableErrors {
		t.Run(errorText, func(t *testing.T) {
			attempts := 0
			session := &coreSession{
				options: ClientOptions{
					Server:      "masque.local",
					ServerPort:  443,
					TemplateTCP: "https://masque.local/masque/tcp/{target_host}/{target_port}",
				},
				tcpRoundTripper: roundTripperFunc(func(req *http.Request) (*http.Response, error) {
					attempts++
					return nil, errors.New(errorText)
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

func TestDialTCPStreamNonRetryableRoundTripErrorDoesNotRetryAndKeepsDialClass(t *testing.T) {
	attempts := 0
	session := &coreSession{
		options: ClientOptions{
			Server:      "masque.local",
			ServerPort:  443,
			TemplateTCP: "https://masque.local/masque/tcp/{target_host}/{target_port}",
		},
		tcpRoundTripper: roundTripperFunc(func(req *http.Request) (*http.Response, error) {
			attempts++
			return nil, errors.New("tls: bad certificate")
		}),
	}
	_, err := session.dialTCPStream(context.Background(), M.ParseSocksaddrHostPort("example.com", 443))
	if !errors.Is(err, ErrTCPConnectStreamFailed) {
		t.Fatalf("expected ErrTCPConnectStreamFailed, got: %v", err)
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
			return nil, errors.New("timeout while connecting")
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
			return nil, errors.New("timeout while connecting")
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
			return nil, errors.New("timeout while connecting")
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
			return nil, errors.New("timeout while connecting")
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

type fakeIPPacketSession struct{}

func (f fakeIPPacketSession) ReadPacket(buffer []byte) (int, error) { return 0, nil }
func (f fakeIPPacketSession) WritePacket(buffer []byte) ([]byte, error) {
	return nil, nil
}
func (f fakeIPPacketSession) Close() error { return nil }

type recordingIPPacketSession struct {
	lastWrite  []byte
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
	s.lastWrite = append([]byte(nil), buffer...)
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
