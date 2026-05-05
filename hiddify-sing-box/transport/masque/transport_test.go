package masque

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"
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
