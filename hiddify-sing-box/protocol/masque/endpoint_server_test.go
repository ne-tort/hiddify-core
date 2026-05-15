package masque

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	connectip "github.com/quic-go/connect-ip-go"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
	TM "github.com/sagernet/sing-box/transport/masque"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/yosida95/uritemplate/v3"
)

func TestMasqueTCPBindFailureRetryable(t *testing.T) {
	t.Parallel()
	win := errors.New("listen tcp 127.0.0.1:65058: bind: An attempt was made to access a socket in a way forbidden by its access permissions.")
	if !masqueTCPBindFailureRetryable(win) {
		t.Fatalf("expected Windows-style bind denial to be retryable")
	}
	if masqueTCPBindFailureRetryable(errors.New("address already in use")) {
		t.Fatalf("conflict error must not be classified as ephemeral-port retry")
	}
}

func TestMasqueConnectIPDataplaneContextDoesNotInheritHTTPRequestCancel(t *testing.T) {
	t.Parallel()
	type ctxKey struct{}
	parent := context.WithValue(context.Background(), ctxKey{}, "marker")
	parent, cancel := context.WithCancel(parent)
	cancel()
	if parent.Err() == nil {
		t.Fatal("parent context should be canceled")
	}
	dc := masqueConnectIPDataplaneContext(parent)
	if dc.Err() != nil {
		t.Fatalf("dataplane context must not inherit request cancellation: %v", dc.Err())
	}
	if got, _ := dc.Value(ctxKey{}).(string); got != "marker" {
		t.Fatalf("expected context values preserved from parent, got %q", got)
	}
}

func TestParseIPDestinationAndPayloadIPv4UDP(t *testing.T) {
	payload := []byte{1, 2, 3, 4, 5}
	packet := makeIPv4UDPPacket(
		netip.MustParseAddr("10.0.0.1"),
		netip.MustParseAddr("10.0.0.2"),
		12345,
		5601,
		payload,
	)
	destination, payloadStart, payloadEnd, err := parseIPDestinationAndPayload(packet)
	if err != nil {
		t.Fatalf("parse ipv4 udp packet: %v", err)
	}
	if !destination.Addr.IsValid() || destination.Addr.String() != "10.0.0.2" {
		t.Fatalf("unexpected destination addr: %v", destination.Addr)
	}
	if destination.Port != 5601 {
		t.Fatalf("unexpected destination port: %d", destination.Port)
	}
	if got := packet[payloadStart:payloadEnd]; string(got) != string(payload) {
		t.Fatalf("unexpected payload slice: %v", got)
	}
}

func TestParseIPDestinationAndPayloadIPv6UDP(t *testing.T) {
	payload := []byte{9, 8, 7, 6}
	packet := makeIPv6UDPPacket(
		netip.MustParseAddr("2001:db8::1"),
		netip.MustParseAddr("2001:db8::2"),
		2000,
		5601,
		payload,
	)
	destination, payloadStart, payloadEnd, err := parseIPDestinationAndPayload(packet)
	if err != nil {
		t.Fatalf("parse ipv6 udp packet: %v", err)
	}
	if !destination.Addr.IsValid() || destination.Addr.String() != "2001:db8::2" {
		t.Fatalf("unexpected destination addr: %v", destination.Addr)
	}
	if destination.Port != 5601 {
		t.Fatalf("unexpected destination port: %d", destination.Port)
	}
	if got := packet[payloadStart:payloadEnd]; string(got) != string(payload) {
		t.Fatalf("unexpected payload slice: %v", got)
	}
}

func TestParseIPDestinationAndPayloadIPv6UDPWithExtensionHeader(t *testing.T) {
	payload := []byte{0xaa, 0xbb, 0xcc, 0xdd}
	packet := makeIPv6UDPPacketWithHopByHop(
		netip.MustParseAddr("2001:db8::1"),
		netip.MustParseAddr("2001:db8::2"),
		2000,
		5601,
		payload,
	)
	destination, payloadStart, payloadEnd, err := parseIPDestinationAndPayload(packet)
	if err != nil {
		t.Fatalf("parse ipv6 udp packet with extension header: %v", err)
	}
	if !destination.Addr.IsValid() || destination.Addr.String() != "2001:db8::2" {
		t.Fatalf("unexpected destination addr: %v", destination.Addr)
	}
	if destination.Port != 5601 {
		t.Fatalf("unexpected destination port: %d", destination.Port)
	}
	if got := packet[payloadStart:payloadEnd]; string(got) != string(payload) {
		t.Fatalf("unexpected payload slice: %v", got)
	}
}

func TestParseIPDestinationAndPayloadIPv4IgnoresTrailingGarbage(t *testing.T) {
	payload := []byte{0xde, 0xad, 0xbe}
	packet := makeIPv4UDPPacket(
		netip.MustParseAddr("10.0.0.1"),
		netip.MustParseAddr("10.0.0.2"),
		12345,
		5601,
		payload,
	)
	packet = append(packet, 0xff, 0xff, 0xff, 0xff)
	destination, ps, pe, err := parseIPDestinationAndPayload(packet)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if pe-ps != len(payload) {
		t.Fatalf("payload span len=%d want %d (raw IP tail must not leak into UDP payload slice)", pe-ps, len(payload))
	}
	if string(packet[ps:pe]) != string(payload) {
		t.Fatalf("payload bytes mismatch")
	}
	if !destination.Addr.IsValid() {
		t.Fatalf("destination")
	}
}

func TestParseIPDestinationAndPayloadIPv4UDPPayloadCutByDeclaredLength(t *testing.T) {
	payload := []byte{0x01, 0x02, 0x03, 0x04}
	packet := makeIPv4UDPPacket(
		netip.MustParseAddr("10.0.0.1"),
		netip.MustParseAddr("10.0.0.2"),
		12000,
		5601,
		payload,
	)
	// Keep IP total length intact, but shrink UDP length so parser must cut payload.
	packet[24] = 0
	packet[25] = 10 // UDP header (8) + 2 payload bytes

	_, payloadStart, payloadEnd, err := parseIPDestinationAndPayload(packet)
	if err != nil {
		t.Fatalf("parse ipv4 udp packet with shortened udpLen: %v", err)
	}
	got := packet[payloadStart:payloadEnd]
	want := payload[:2]
	if string(got) != string(want) {
		t.Fatalf("unexpected payload after udpLen cut: got=%v want=%v", got, want)
	}
}

func TestParseIPDestinationAndPayloadMalformed(t *testing.T) {
	tests := []struct {
		name   string
		packet []byte
	}{
		{name: "empty", packet: nil},
		{name: "bad-version", packet: []byte{0x20, 0x00, 0x00}},
		{name: "truncated-ipv4", packet: []byte{0x45, 0x00, 0x00, 0x10}},
		{name: "truncated-ipv6", packet: []byte{0x60, 0x00, 0x00, 0x00, 0x00, 0x08, 17}},
		{name: "malformed-ipv6-extension-chain", packet: []byte{0x60, 0x00, 0x00, 0x00, 0x00, 0x08, 0, 64}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, _, _, err := parseIPDestinationAndPayload(tc.packet)
			if err == nil {
				t.Fatal("expected parse error")
			}
		})
	}
}

func TestParseIPDestinationAndPayloadIPv6InvalidExtensionHeaderLengthFailClosed(t *testing.T) {
	packet := makeIPv6UDPPacketWithHopByHop(
		netip.MustParseAddr("2001:db8::1"),
		netip.MustParseAddr("2001:db8::2"),
		2000,
		5601,
		[]byte{0xaa, 0xbb, 0xcc},
	)
	// Corrupt ext header len: requires 256 bytes, which exceeds packet size.
	packet[41] = 31

	_, _, _, err := parseIPDestinationAndPayload(packet)
	if err == nil {
		t.Fatal("expected fail-closed parse error for malformed ipv6 extension header length")
	}
}

func TestConnectIPMaxICMPRelayInvariant(t *testing.T) {
	if connectIPMaxICMPRelay < 1 {
		t.Fatalf("connectIPMaxICMPRelay must be positive, got %d", connectIPMaxICMPRelay)
	}
}

func TestConnectIPRequestErrorStatusAndClass(t *testing.T) {
	templateUnsupported := uritemplate.MustNew("https://localhost:1234/masque/ip/{unsupported}")
	unsupportedReq := makeConnectIPTestRequest(t, "https://localhost:1234/masque/ip/value")
	_, unsupportedErr := connectip.ParseRequest(unsupportedReq, templateUnsupported)
	if unsupportedErr == nil {
		t.Fatal("expected parse error for unsupported template variable")
	}
	if got := connectIPRequestErrorHTTPStatus(unsupportedErr); got != 501 {
		t.Fatalf("unexpected status for unsupported variable: got=%d want=501", got)
	}
	if got := connectIPRequestErrorClass(connectIPRequestErrorHTTPStatus(unsupportedErr)); got != TM.ErrorClassCapability {
		t.Fatalf("unexpected class for unsupported variable: got=%s want=%s", got, TM.ErrorClassCapability)
	}

	templateMalformed := uritemplate.MustNew("https://localhost:1234/masque/ip/{target}/{ipproto}")
	malformedReq := makeConnectIPTestRequest(t, "https://localhost:1234/masque/ip/not-a-prefix/17")
	_, malformedErr := connectip.ParseRequest(malformedReq, templateMalformed)
	if malformedErr == nil {
		t.Fatal("expected parse error for malformed target")
	}
	if got := connectIPRequestErrorHTTPStatus(malformedErr); got != 400 {
		t.Fatalf("unexpected status for malformed target: got=%d want=400", got)
	}
	if got := connectIPRequestErrorClass(connectIPRequestErrorHTTPStatus(malformedErr)); got != TM.ErrorClassCapability {
		t.Fatalf("unexpected class for malformed target: got=%s want=%s", got, TM.ErrorClassCapability)
	}

	if got := connectIPRequestErrorHTTPStatus(errors.New("generic parse issue")); got != 400 {
		t.Fatalf("unexpected fallback status for generic parse error: got=%d want=400", got)
	}
	if got := connectIPRequestErrorClass(418); got != TM.ErrorClassUnknown {
		t.Fatalf("unexpected fallback class for unknown status: got=%s want=%s", got, TM.ErrorClassUnknown)
	}
}

func TestMasqueConnectIPRequestForParseRelaxedAuthority(t *testing.T) {
	t.Parallel()
	template := uritemplate.MustNew("https://127.0.0.1:4438/masque/ip")
	req := makeConnectIPTestRequest(t, "https://127.0.0.1:4438/masque/ip")
	req.Host = "193.233.216.26:4438"
	if _, err := connectip.ParseRequest(req, template); err == nil {
		t.Fatal("expected strict host mismatch without relaxed parse request")
	}
	parseR := masqueHTTPRequestForTemplateParse(req, template, true)
	if parseR.Host != "127.0.0.1:4438" {
		t.Fatalf("relaxed parse host: got %q want 127.0.0.1:4438", parseR.Host)
	}
	if _, err := connectip.ParseRequest(parseR, template); err != nil {
		t.Fatalf("relaxed parse request: %v", err)
	}
}

func TestConnectIPRouteAdvertiseErrorClass(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	testCases := []struct {
		name   string
		routes []connectip.IPRoute
	}{
		{
			name: "unordered",
			routes: []connectip.IPRoute{
				{StartIP: netip.MustParseAddr("10.0.0.10"), EndIP: netip.MustParseAddr("10.0.0.20"), IPProtocol: 0},
				{StartIP: netip.MustParseAddr("10.0.0.1"), EndIP: netip.MustParseAddr("10.0.0.5"), IPProtocol: 0},
			},
		},
		{
			name: "overlap",
			routes: []connectip.IPRoute{
				{StartIP: netip.MustParseAddr("10.0.0.1"), EndIP: netip.MustParseAddr("10.0.0.10"), IPProtocol: 0},
				{StartIP: netip.MustParseAddr("10.0.0.10"), EndIP: netip.MustParseAddr("10.0.0.20"), IPProtocol: 0},
			},
		},
		{
			name: "mixed_family_range",
			routes: []connectip.IPRoute{
				{StartIP: netip.MustParseAddr("0.0.0.0"), EndIP: netip.MustParseAddr("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"), IPProtocol: 0},
			},
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := new(connectip.Conn).AdvertiseRoute(ctx, tc.routes)
			if err == nil {
				t.Fatal("expected invalid route advertisement error")
			}
			if !errors.Is(err, connectip.ErrInvalidRouteAdvertisement) {
				t.Fatalf("expected typed invalid route advertisement error, got: %v", err)
			}
			if got := connectIPRouteAdvertiseErrorClass(err); got != TM.ErrorClassCapability {
				t.Fatalf("unexpected class for invalid route advertisement: got=%s want=%s err=%v", got, TM.ErrorClassCapability, err)
			}
		})
	}

	if got := connectIPRouteAdvertiseErrorClass(errors.New("transport write failed")); got != TM.ErrorClassTransport {
		t.Fatalf("unexpected class for generic route advertise failure: got=%s want=%s", got, TM.ErrorClassTransport)
	}
	if got := connectIPRouteAdvertiseErrorClass(net.ErrClosed); got != TM.ErrorClassLifecycle {
		t.Fatalf("unexpected class for net.ErrClosed route advertise failure: got=%s want=%s", got, TM.ErrorClassLifecycle)
	}
	if got := connectIPRouteAdvertiseErrorClass(&connectip.CloseError{Remote: true}); got != TM.ErrorClassLifecycle {
		t.Fatalf("unexpected class for remote close route advertise failure: got=%s want=%s", got, TM.ErrorClassLifecycle)
	}
	if got := connectIPRouteAdvertiseErrorClass(nil); got != TM.ErrorClassUnknown {
		t.Fatalf("unexpected class for nil route advertise failure: got=%s want=%s", got, TM.ErrorClassUnknown)
	}
}

func TestConnectIPRouteAdvertisePeerCloseLifecycleParity(t *testing.T) {
	actualErr := errors.Join(
		errors.New("route advertisement validation rejected"),
		connectip.ErrInvalidRouteAdvertisement,
	)
	actualClass := connectIPRouteAdvertiseErrorClass(actualErr)
	if actualClass != TM.ErrorClassCapability {
		t.Fatalf("unexpected class for invalid route advertisement validation reject: got=%s want=%s err=%v", actualClass, TM.ErrorClassCapability, actualErr)
	}

	testCases := []struct {
		name string
		err  error
	}{
		{
			name: "wrapped_net_err_closed",
			err:  errors.Join(errors.New("route advertise not-ready"), net.ErrClosed),
		},
		{
			name: "wrapped_remote_close_error",
			err:  errors.Join(errors.New("peer aborted route advertise"), &connectip.CloseError{Remote: true}),
		},
	}
	resultClass := TM.ErrorClassUnknown
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got := connectIPRouteAdvertiseErrorClass(tc.err)
			if got != TM.ErrorClassLifecycle {
				t.Fatalf("unexpected class for peer-close lifecycle parity: got=%s want=%s err=%v", got, TM.ErrorClassLifecycle, tc.err)
			}
			resultClass = got
		})
	}

	writeRouteAdvertiseDualSignalArtifactIfRequested(t, actualClass, resultClass)
}

func TestServerEndpointDialContextRejectsInvalidDestinationAsCapability(t *testing.T) {
	endpoint := &ServerEndpoint{}
	_, err := endpoint.DialContext(context.Background(), "tcp", M.Socksaddr{})
	if err == nil {
		t.Fatal("expected invalid destination to be rejected")
	}
	if !errors.Is(err, TM.ErrCapability) {
		t.Fatalf("expected ErrCapability for invalid destination, got: %v", err)
	}
	if got := TM.ClassifyError(err); got != TM.ErrorClassCapability {
		t.Fatalf("expected capability class for invalid destination, got: %s", got)
	}
}

func writeRouteAdvertiseDualSignalArtifactIfRequested(t *testing.T, actualClass, resultClass TM.ErrorClass) {
	t.Helper()

	artifactPath := os.Getenv("MASQUE_ROUTE_ADVERTISE_ARTIFACT_PATH")
	if artifactPath == "" {
		return
	}

	artifact := map[string]any{
		"ok":                     actualClass == TM.ErrorClassCapability && resultClass == TM.ErrorClassLifecycle,
		"actual_error_class":     string(actualClass),
		"result_error_class":     string(resultClass),
		"error_class_consistent": actualClass == TM.ErrorClassCapability && resultClass == TM.ErrorClassLifecycle,
		"error_source":           "runtime",
	}

	raw, err := json.MarshalIndent(artifact, "", "  ")
	if err != nil {
		t.Fatalf("marshal route advertise dual-signal artifact: %v", err)
	}
	if err := os.WriteFile(artifactPath, raw, 0o644); err != nil {
		t.Fatalf("write route advertise dual-signal artifact: %v", err)
	}
}

func TestServerEndpointLifecycleStartIsReadyCloseTwice(t *testing.T) {
	certPath, keyPath := writeServerTestCertificate(t)
	ep := &ServerEndpoint{
		options: option.MasqueEndpointOptions{
			Listen:      "127.0.0.1",
			ListenPort:  0,
			InboundTLS: &option.InboundTLSOptions{
				Enabled:         true,
				CertificatePath: certPath,
				KeyPath:         keyPath,
			},
		},
	}
	if ep.IsReady() {
		t.Fatal("server endpoint must not be ready before Start")
	}
	if err := ep.Start(adapter.StartStateStart); err != nil {
		t.Fatalf("server start failed: %v", err)
	}
	if !ep.IsReady() {
		t.Fatal("server endpoint must be ready immediately after successful Start")
	}
	closeDone := make(chan error, 1)
	go func() {
		closeDone <- ep.Close()
	}()
	select {
	case err := <-closeDone:
		if err != nil {
			t.Fatalf("first close failed: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("first close timed out (potential lifecycle hang)")
	}
	if ep.IsReady() {
		t.Fatal("server endpoint must not be ready after Close")
	}
	closeDone = make(chan error, 1)
	go func() {
		closeDone <- ep.Close()
	}()
	select {
	case err := <-closeDone:
		if err != nil {
			t.Fatalf("second close failed: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("second close timed out (close must stay idempotent)")
	}
}

func TestServerEndpointStartInvalidCertificateFailsFast(t *testing.T) {
	tmpDir := t.TempDir()
	certPath := filepath.Join(tmpDir, "invalid.crt")
	keyPath := filepath.Join(tmpDir, "invalid.key")
	if err := os.WriteFile(certPath, []byte("not-a-certificate"), 0o600); err != nil {
		t.Fatalf("write invalid cert: %v", err)
	}
	if err := os.WriteFile(keyPath, []byte("not-a-private-key"), 0o600); err != nil {
		t.Fatalf("write invalid key: %v", err)
	}
	ep := &ServerEndpoint{
		options: option.MasqueEndpointOptions{
			Listen:      "127.0.0.1",
			ListenPort:  0,
			InboundTLS: &option.InboundTLSOptions{
				Enabled:         true,
				CertificatePath: certPath,
				KeyPath:         keyPath,
			},
		},
	}
	err := ep.Start(adapter.StartStateStart)
	if err == nil {
		t.Fatal("expected Start to fail fast with invalid certificate/key")
	}
	if ep.IsReady() {
		t.Fatal("server endpoint must remain not ready after failed Start")
	}
	closeDone := make(chan error, 1)
	go func() {
		closeDone <- ep.Close()
	}()
	select {
	case closeErr := <-closeDone:
		if closeErr != nil {
			t.Fatalf("close after failed start should stay safe, got: %v", closeErr)
		}
	case <-time.After(time.Second):
		t.Fatal("close after failed start timed out (unexpected lifecycle hang)")
	}
}

func TestServerEndpointStartListenConflictFailsFast(t *testing.T) {
	certPath, keyPath := writeServerTestCertificate(t)
	conflictConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve udp port for conflict: %v", err)
	}
	defer func() {
		_ = conflictConn.Close()
	}()
	conflictAddr, ok := conflictConn.LocalAddr().(*net.UDPAddr)
	if !ok {
		t.Fatalf("unexpected conflict addr type: %T", conflictConn.LocalAddr())
	}
	ep := &ServerEndpoint{
		options: option.MasqueEndpointOptions{
			Listen:      "127.0.0.1",
			ListenPort:  uint16(conflictAddr.Port),
			InboundTLS: &option.InboundTLSOptions{
				Enabled:         true,
				CertificatePath: certPath,
				KeyPath:         keyPath,
			},
		},
	}
	startErr := ep.Start(adapter.StartStateStart)
	if startErr == nil {
		t.Fatal("expected Start to fail fast on listen udp conflict")
	}
	if ep.IsReady() {
		t.Fatal("server endpoint must remain not ready after listen conflict")
	}
	closeDone := make(chan error, 1)
	go func() {
		closeDone <- ep.Close()
	}()
	select {
	case closeErr := <-closeDone:
		if closeErr != nil {
			t.Fatalf("close after listen conflict should stay safe, got: %v", closeErr)
		}
	case <-time.After(time.Second):
		t.Fatal("close after listen conflict timed out (unexpected lifecycle hang)")
	}
	if _, listenErr := net.ListenPacket("udp", net.JoinHostPort("127.0.0.1", strconv.Itoa(conflictAddr.Port))); listenErr == nil {
		t.Fatal("expected reserved conflict socket to keep the listen port busy during test")
	}
}

func TestServerEndpointStartNonStartStageNoOpThenRegularStartWorks(t *testing.T) {
	certPath, keyPath := writeServerTestCertificate(t)
	ep := &ServerEndpoint{
		options: option.MasqueEndpointOptions{
			Listen:      "127.0.0.1",
			ListenPort:  0,
			InboundTLS: &option.InboundTLSOptions{
				Enabled:         true,
				CertificatePath: certPath,
				KeyPath:         keyPath,
			},
		},
	}
	if err := ep.Start(adapter.StartStateInitialize); err != nil {
		t.Fatalf("expected non-start stage to be no-op without error, got: %v", err)
	}
	if ep.IsReady() {
		t.Fatal("server endpoint must stay not ready after non-start stage no-op")
	}
	if ep.server != nil || ep.packetConn != nil || ep.tcpTLSListener != nil || ep.http2Server != nil {
		t.Fatal("non-start stage must not initialize server listener resources")
	}
	if err := ep.Start(adapter.StartStateStart); err != nil {
		t.Fatalf("expected regular start after non-start stage no-op to succeed, got: %v", err)
	}
	if !ep.IsReady() {
		t.Fatal("server endpoint must become ready after regular Start")
	}
	if err := ep.Close(); err != nil {
		t.Fatalf("close after regular start failed: %v", err)
	}
}

func TestServerEndpointStartNonStartStagesAreIdempotentAndDoNotContaminateStartError(t *testing.T) {
	certPath, keyPath := writeServerTestCertificate(t)
	ep := &ServerEndpoint{
		options: option.MasqueEndpointOptions{
			Listen:      "127.0.0.1",
			ListenPort:  0,
			InboundTLS: &option.InboundTLSOptions{
				Enabled:         true,
				CertificatePath: certPath,
				KeyPath:         keyPath,
			},
		},
	}
	ep.startErr.Store(startErrorState{err: net.ErrClosed})
	for _, stage := range []adapter.StartStage{
		adapter.StartStateInitialize,
		adapter.StartStatePostStart,
		adapter.StartStateStarted,
	} {
		if err := ep.Start(stage); err != nil {
			t.Fatalf("expected non-start stage %v to be no-op, got: %v", stage, err)
		}
	}
	if ep.server != nil || ep.packetConn != nil || ep.tcpTLSListener != nil || ep.http2Server != nil {
		t.Fatal("non-start stages must not initialize server listener resources")
	}
	if err := ep.Start(adapter.StartStateStart); err != nil {
		t.Fatalf("expected regular start after repeated non-start stages to succeed, got: %v", err)
	}
	if !ep.IsReady() {
		t.Fatal("server endpoint must be ready after successful Start and stale startErr must be cleared")
	}
	if err := ep.Close(); err != nil {
		t.Fatalf("close after regular start failed: %v", err)
	}
}

func TestServerEndpointServeFailureThenRestartClearsStartErrorAndRestoresReady(t *testing.T) {
	certPath, keyPath := writeServerTestCertificate(t)
	ep := &ServerEndpoint{
		options: option.MasqueEndpointOptions{
			Listen:      "127.0.0.1",
			ListenPort:  0,
			InboundTLS: &option.InboundTLSOptions{
				Enabled:         true,
				CertificatePath: certPath,
				KeyPath:         keyPath,
			},
		},
	}
	if err := ep.Start(adapter.StartStateStart); err != nil {
		t.Fatalf("initial start failed: %v", err)
	}
	if !ep.IsReady() {
		t.Fatal("server must be ready after initial start")
	}
	if ep.packetConn == nil {
		t.Fatal("expected packetConn to be initialized after start")
	}
	_ = ep.packetConn.Close()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if ep.lastStartError() != nil && !ep.IsReady() {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if ep.lastStartError() == nil {
		t.Fatal("expected serve failure to populate startErr after forced packetConn close")
	}
	if ep.IsReady() {
		t.Fatal("server must transition to not-ready after serve failure")
	}
	if err := ep.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
		t.Fatalf("close after serve failure failed: %v", err)
	}
	if err := ep.Start(adapter.StartStateStart); err != nil {
		t.Fatalf("restart after serve failure failed: %v", err)
	}
	if !ep.IsReady() {
		t.Fatal("server must become ready after successful restart and stale startErr must be cleared")
	}
	if err := ep.Close(); err != nil {
		t.Fatalf("final close failed: %v", err)
	}
}

func TestServerEndpointConcurrentCloseDoesNotPoisonStartError(t *testing.T) {
	certPath, keyPath := writeServerTestCertificate(t)
	ep := &ServerEndpoint{
		options: option.MasqueEndpointOptions{
			Listen:      "127.0.0.1",
			ListenPort:  0,
			InboundTLS: &option.InboundTLSOptions{
				Enabled:         true,
				CertificatePath: certPath,
				KeyPath:         keyPath,
			},
		},
	}
	if err := ep.Start(adapter.StartStateStart); err != nil {
		t.Fatalf("start failed: %v", err)
	}
	if !ep.IsReady() {
		t.Fatal("server must be ready after start")
	}
	closeDone := make(chan error, 1)
	go func() {
		closeDone <- ep.Close()
	}()
	select {
	case err := <-closeDone:
		if err != nil {
			t.Fatalf("close failed: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("close timed out")
	}
	deadline := time.Now().Add(300 * time.Millisecond)
	for time.Now().Before(deadline) {
		if ep.lastStartError() != nil {
			t.Fatalf("expected no fatal startErr on normal shutdown, got: %v", ep.lastStartError())
		}
		time.Sleep(10 * time.Millisecond)
	}
	if ep.IsReady() {
		t.Fatal("server must remain not-ready after close")
	}
}

func makeIPv4UDPPacket(src, dst netip.Addr, srcPort, dstPort uint16, payload []byte) []byte {
	ihl := 20
	udpLen := 8 + len(payload)
	totalLen := ihl + udpLen
	packet := make([]byte, totalLen)
	packet[0] = 0x45
	packet[2] = byte(totalLen >> 8)
	packet[3] = byte(totalLen)
	packet[8] = 64
	packet[9] = 17
	copy(packet[12:16], src.AsSlice())
	copy(packet[16:20], dst.AsSlice())
	packet[ihl+0] = byte(srcPort >> 8)
	packet[ihl+1] = byte(srcPort)
	packet[ihl+2] = byte(dstPort >> 8)
	packet[ihl+3] = byte(dstPort)
	packet[ihl+4] = byte(udpLen >> 8)
	packet[ihl+5] = byte(udpLen)
	copy(packet[ihl+8:], payload)
	return packet
}

func makeIPv6UDPPacket(src, dst netip.Addr, srcPort, dstPort uint16, payload []byte) []byte {
	const headerLen = 40
	udpLen := 8 + len(payload)
	packet := make([]byte, headerLen+udpLen)
	packet[0] = 0x60
	packet[4] = byte(udpLen >> 8)
	packet[5] = byte(udpLen)
	packet[6] = 17
	packet[7] = 64
	copy(packet[8:24], src.AsSlice())
	copy(packet[24:40], dst.AsSlice())
	packet[40] = byte(srcPort >> 8)
	packet[41] = byte(srcPort)
	packet[42] = byte(dstPort >> 8)
	packet[43] = byte(dstPort)
	packet[44] = byte(udpLen >> 8)
	packet[45] = byte(udpLen)
	copy(packet[48:], payload)
	return packet
}

func makeIPv6UDPPacketWithHopByHop(src, dst netip.Addr, srcPort, dstPort uint16, payload []byte) []byte {
	const (
		baseHeaderLen = 40
		extHeaderLen  = 8
	)
	udpLen := 8 + len(payload)
	packet := make([]byte, baseHeaderLen+extHeaderLen+udpLen)
	packet[0] = 0x60
	packet[4] = byte((extHeaderLen + udpLen) >> 8)
	packet[5] = byte(extHeaderLen + udpLen)
	packet[6] = 0 // Hop-by-Hop extension header
	packet[7] = 64
	copy(packet[8:24], src.AsSlice())
	copy(packet[24:40], dst.AsSlice())

	packet[40] = 17 // next header: UDP
	packet[41] = 0  // extension header length in 8-byte units (0 => 8 bytes)
	// bytes [42:48] keep zero as extension header payload.

	udpOffset := baseHeaderLen + extHeaderLen
	packet[udpOffset+0] = byte(srcPort >> 8)
	packet[udpOffset+1] = byte(srcPort)
	packet[udpOffset+2] = byte(dstPort >> 8)
	packet[udpOffset+3] = byte(dstPort)
	packet[udpOffset+4] = byte(udpLen >> 8)
	packet[udpOffset+5] = byte(udpLen)
	copy(packet[udpOffset+8:], payload)
	return packet
}

func writeServerTestCertificate(t *testing.T) (string, string) {
	t.Helper()
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate rsa key: %v", err)
	}
	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		t.Fatalf("generate cert serial: %v", err)
	}
	certTemplate := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: "masque-test.local",
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"masque-test.local", "localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, certTemplate, certTemplate, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	tmpDir := t.TempDir()
	certPath := filepath.Join(tmpDir, "server.crt")
	keyPath := filepath.Join(tmpDir, "server.key")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	keyDER := x509.MarshalPKCS1PrivateKey(privateKey)
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	return certPath, keyPath
}

func makeConnectIPTestRequest(t *testing.T, rawURL string) *http.Request {
	t.Helper()
	req, err := http.NewRequest(http.MethodConnect, rawURL, nil)
	if err != nil {
		t.Fatalf("new connect-ip request: %v", err)
	}
	req.Proto = "connect-ip"
	req.Host = "localhost:1234"
	req.Header.Set("Capsule-Protocol", "?1")
	return req
}
