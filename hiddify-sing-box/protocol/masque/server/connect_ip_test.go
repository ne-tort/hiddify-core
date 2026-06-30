package server

import (
	"github.com/sagernet/sing-box/transport/masque/session"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"os"
	"testing"
	"time"

	connectip "github.com/quic-go/connect-ip-go"
	cip "github.com/sagernet/sing-box/transport/masque/connectip"
	fwd "github.com/sagernet/sing-box/transport/masque/forwarder"
	"github.com/sagernet/sing/common/buf"
	"github.com/yosida95/uritemplate/v3"
)

func TestDataplaneContextDoesNotInheritHTTPRequestCancel(t *testing.T) {
	t.Parallel()
	type ctxKey struct{}
	parent := context.WithValue(context.Background(), ctxKey{}, "marker")
	parent, cancel := context.WithCancel(parent)
	cancel()
	if parent.Err() == nil {
		t.Fatal("parent context should be canceled")
	}
	dc := DataplaneContext(parent)
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
	destination, payloadStart, payloadEnd, err := ParseIPDestinationAndPayload(packet)
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
	destination, payloadStart, payloadEnd, err := ParseIPDestinationAndPayload(packet)
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
	destination, payloadStart, payloadEnd, err := ParseIPDestinationAndPayload(packet)
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
	destination, ps, pe, err := ParseIPDestinationAndPayload(packet)
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
	packet[24] = 0
	packet[25] = 10

	_, payloadStart, payloadEnd, err := ParseIPDestinationAndPayload(packet)
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
			_, _, _, err := ParseIPDestinationAndPayload(tc.packet)
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
	packet[41] = 31

	_, _, _, err := ParseIPDestinationAndPayload(packet)
	if err == nil {
		t.Fatal("expected fail-closed parse error for malformed ipv6 extension header length")
	}
}

func TestConnectIPMaxICMPRelayInvariant(t *testing.T) {
	if ConnectIPMaxICMPRelay < 1 {
		t.Fatalf("ConnectIPMaxICMPRelay must be positive, got %d", ConnectIPMaxICMPRelay)
	}
	if ConnectIPMaxICMPRelay != 8 {
		t.Fatalf("ConnectIPMaxICMPRelay=%d want 8 (CLIENT-SERVER-CONTRACTS)", ConnectIPMaxICMPRelay)
	}
}

func TestConnectIPMaxParseDropPerReadInvariant(t *testing.T) {
	if ConnectIPMaxParseDropPerRead < 1 {
		t.Fatalf("ConnectIPMaxParseDropPerRead must be positive, got %d", ConnectIPMaxParseDropPerRead)
	}
	if ConnectIPMaxParseDropPerRead != 64 {
		t.Fatalf("ConnectIPMaxParseDropPerRead=%d want 64", ConnectIPMaxParseDropPerRead)
	}
}

func TestConnectIPRequestErrorStatusAndClass(t *testing.T) {
	templateUnsupported := uritemplate.MustNew("https://localhost:1234/masque/ip/{unsupported}")
	unsupportedReq := makeConnectIPTestRequest(t, "https://localhost:1234/masque/ip/value")
	_, unsupportedErr := connectip.ParseRequest(unsupportedReq, templateUnsupported)
	if unsupportedErr == nil {
		t.Fatal("expected parse error for unsupported template variable")
	}
	if got := ConnectIPRequestErrorHTTPStatus(unsupportedErr); got != 501 {
		t.Fatalf("unexpected status for unsupported variable: got=%d want=501", got)
	}
	if got := ConnectIPRequestErrorClass(ConnectIPRequestErrorHTTPStatus(unsupportedErr)); got != session.ErrorClassCapability {
		t.Fatalf("unexpected class for unsupported variable: got=%s want=%s", got, session.ErrorClassCapability)
	}

	templateMalformed := uritemplate.MustNew("https://localhost:1234/masque/ip/{target}/{ipproto}")
	malformedReq := makeConnectIPTestRequest(t, "https://localhost:1234/masque/ip/not-a-prefix/17")
	_, malformedErr := connectip.ParseRequest(malformedReq, templateMalformed)
	if malformedErr == nil {
		t.Fatal("expected parse error for malformed target")
	}
	if got := ConnectIPRequestErrorHTTPStatus(malformedErr); got != 400 {
		t.Fatalf("unexpected status for malformed target: got=%d want=400", got)
	}
	if got := ConnectIPRequestErrorClass(ConnectIPRequestErrorHTTPStatus(malformedErr)); got != session.ErrorClassCapability {
		t.Fatalf("unexpected class for malformed target: got=%s want=%s", got, session.ErrorClassCapability)
	}

	if got := ConnectIPRequestErrorHTTPStatus(errors.New("generic parse issue")); got != 400 {
		t.Fatalf("unexpected fallback status for generic parse error: got=%d want=400", got)
	}
	if got := ConnectIPRequestErrorClass(418); got != session.ErrorClassUnknown {
		t.Fatalf("unexpected fallback class for unknown status: got=%s want=%s", got, session.ErrorClassUnknown)
	}
}

func TestConnectIPRouteSetupTimeoutDefault(t *testing.T) {
	t.Setenv("MASQUE_CONNECT_IP_ROUTE_SETUP_TIMEOUT", "")
	if got := ConnectIPRouteSetupTimeout(); got != defaultConnectIPRouteSetupTimeout {
		t.Fatalf("default timeout=%v want %v", got, defaultConnectIPRouteSetupTimeout)
	}
}

func TestConnectIPRouteSetupTimeoutEnvOverride(t *testing.T) {
	t.Setenv("MASQUE_CONNECT_IP_ROUTE_SETUP_TIMEOUT", "5s")
	if got := ConnectIPRouteSetupTimeout(); got != 5*time.Second {
		t.Fatalf("env timeout=%v want 5s", got)
	}
}

func TestConnectIPRouteSetupTimeoutEnvInvalidFallsBack(t *testing.T) {
	t.Setenv("MASQUE_CONNECT_IP_ROUTE_SETUP_TIMEOUT", "not-a-duration")
	if got := ConnectIPRouteSetupTimeout(); got != defaultConnectIPRouteSetupTimeout {
		t.Fatalf("invalid env timeout=%v want default %v", got, defaultConnectIPRouteSetupTimeout)
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
			if got := ConnectIPRouteAdvertiseErrorClass(err); got != session.ErrorClassCapability {
				t.Fatalf("unexpected class for invalid route advertisement: got=%s want=%s err=%v", got, session.ErrorClassCapability, err)
			}
		})
	}

	if got := ConnectIPRouteAdvertiseErrorClass(errors.New("transport write failed")); got != session.ErrorClassTransport {
		t.Fatalf("unexpected class for generic route advertise failure: got=%s want=%s", got, session.ErrorClassTransport)
	}
	if got := ConnectIPRouteAdvertiseErrorClass(net.ErrClosed); got != session.ErrorClassLifecycle {
		t.Fatalf("unexpected class for net.ErrClosed route advertise failure: got=%s want=%s", got, session.ErrorClassLifecycle)
	}
	if got := ConnectIPRouteAdvertiseErrorClass(&connectip.CloseError{Remote: true}); got != session.ErrorClassLifecycle {
		t.Fatalf("unexpected class for remote close route advertise failure: got=%s want=%s", got, session.ErrorClassLifecycle)
	}
	if got := ConnectIPRouteAdvertiseErrorClass(nil); got != session.ErrorClassUnknown {
		t.Fatalf("unexpected class for nil route advertise failure: got=%s want=%s", got, session.ErrorClassUnknown)
	}
}

func TestConnectIPRouteAdvertisePeerCloseLifecycleParity(t *testing.T) {
	actualErr := errors.Join(
		errors.New("route advertisement validation rejected"),
		connectip.ErrInvalidRouteAdvertisement,
	)
	actualClass := ConnectIPRouteAdvertiseErrorClass(actualErr)
	if actualClass != session.ErrorClassCapability {
		t.Fatalf("unexpected class for invalid route advertisement validation reject: got=%s want=%s err=%v", actualClass, session.ErrorClassCapability, actualErr)
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
	resultClass := session.ErrorClassUnknown
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got := ConnectIPRouteAdvertiseErrorClass(tc.err)
			if got != session.ErrorClassLifecycle {
				t.Fatalf("unexpected class for peer-close lifecycle parity: got=%s want=%s err=%v", got, session.ErrorClassLifecycle, tc.err)
			}
			resultClass = got
		})
	}

	writeRouteAdvertiseDualSignalArtifactIfRequested(t, actualClass, resultClass)
}

func TestConnectIPServerWriteErrorClass(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		err  error
		want session.ErrorClass
	}{
		{name: "nil", err: nil, want: session.ErrorClassUnknown},
		{name: "closed", err: net.ErrClosed, want: session.ErrorClassLifecycle},
		{name: "canceled", err: context.Canceled, want: session.ErrorClassLifecycle},
		{name: "remote_close", err: &connectip.CloseError{Remote: true}, want: session.ErrorClassLifecycle},
		{name: "flow_forwarding", err: connectip.ErrFlowForwardingUnsupported, want: session.ErrorClassCapability},
		{name: "deadline", err: context.DeadlineExceeded, want: session.ErrorClassTransport},
		{name: "fatal", err: errors.New("unexpected write fault"), want: session.ErrorClassUnknown},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := ConnectIPServerWriteErrorClass(tc.err); got != tc.want {
				t.Fatalf("ConnectIPServerWriteErrorClass() = %s want %s", got, tc.want)
			}
		})
	}
}

// TestConnectIPClientWriteCeilingServerReadPacketParity verifies that the largest IPv4
// datagram the client may WritePacket (datagram ceiling) is accepted by server ReadPacket.
func TestConnectIPClientWriteCeilingServerReadPacketParity(t *testing.T) {
	t.Parallel()
	ceiling := cip.DefaultDatagramCeilingMax
	maxDatagram := cip.MaxIPv4Datagram(ceiling)
	wireSlack := cip.DefaultDatagramCeilingMax - cip.MaxIPv4WireBytes
	if maxDatagram+wireSlack != ceiling {
		t.Fatalf("MaxIPv4Datagram+wireSlack=%d want ceiling %d", maxDatagram+wireSlack, ceiling)
	}
	if maxDatagram != fwd.MaxIPv4WireBytes {
		t.Fatalf("server forwarder max=%d want %d", maxDatagram, fwd.MaxIPv4WireBytes)
	}

	const ipv4Header = 20
	const udpHeader = 8
	payloadLen := maxDatagram - ipv4Header - udpHeader
	if payloadLen <= 0 {
		t.Fatalf("invalid payload len for max datagram")
	}
	payload := bytes.Repeat([]byte{0xab}, payloadLen)
	packet := makeIPv4UDPPacket(
		netip.MustParseAddr("10.0.0.1"),
		netip.MustParseAddr("10.0.0.2"),
		12345,
		5601,
		payload,
	)
	if len(packet) != maxDatagram {
		t.Fatalf("built packet len=%d want max datagram %d", len(packet), maxDatagram)
	}
	if len(packet) > ceiling {
		t.Fatalf("max IPv4 datagram %d exceeds client WritePacket ceiling %d", len(packet), ceiling)
	}

	mock := &staticPacketPlaneConn{readPacket: packet}
	npc := NewConnectIPNetPacketConn(mock)
	buffer := buf.NewSize(maxDatagram)
	destination, err := npc.ReadPacket(buffer)
	if err != nil {
		t.Fatalf("server ReadPacket max-size datagram: %v", err)
	}
	if !destination.Addr.IsValid() || destination.Addr.String() != "10.0.0.2" {
		t.Fatalf("unexpected destination: %v", destination.Addr)
	}
	if buffer.Len() != payloadLen {
		t.Fatalf("payload len=%d want %d", buffer.Len(), payloadLen)
	}
}

type staticPacketPlaneConn struct {
	readPacket []byte
	closed     bool
}

func (c *staticPacketPlaneConn) ReadPacket(b []byte) (int, error) {
	if c.closed {
		return 0, net.ErrClosed
	}
	if len(c.readPacket) == 0 {
		return 0, ioEOF{}
	}
	n := copy(b, c.readPacket)
	c.readPacket = nil
	return n, nil
}

func (c *staticPacketPlaneConn) WritePacket(b []byte) ([]byte, error) {
	return nil, nil
}

func (c *staticPacketPlaneConn) Close() error {
	c.closed = true
	return nil
}

func (c *staticPacketPlaneConn) CurrentPeerPrefixes() []netip.Prefix {
	return nil
}

type ioEOF struct{}

func (ioEOF) Error() string { return "EOF" }

func writeRouteAdvertiseDualSignalArtifactIfRequested(t *testing.T, actualClass, resultClass session.ErrorClass) {
	t.Helper()

	artifactPath := os.Getenv("MASQUE_ROUTE_ADVERTISE_ARTIFACT_PATH")
	if artifactPath == "" {
		return
	}

	artifact := map[string]any{
		"ok":                     actualClass == session.ErrorClassCapability && resultClass == session.ErrorClassLifecycle,
		"actual_error_class":     string(actualClass),
		"result_error_class":     string(resultClass),
		"error_class_consistent": actualClass == session.ErrorClassCapability && resultClass == session.ErrorClassLifecycle,
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
	packet[6] = 0
	packet[7] = 64
	copy(packet[8:24], src.AsSlice())
	copy(packet[24:40], dst.AsSlice())

	packet[40] = 17
	packet[41] = 0

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
