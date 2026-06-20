package masque

import (
	"context"
	"net/netip"
	"testing"

	"github.com/quic-go/quic-go/http3"
	"github.com/sagernet/sing-box/option"
	cip "github.com/sagernet/sing-box/transport/masque/connectip"
	"github.com/sagernet/gvisor/pkg/tcpip/header"
)

func TestConnectIPIngressAckWakeAfterDeliver(t *testing.T) {
	t.Parallel()
	pkt := buildIngressBridgeTestACK(t)

	sess := &packetPipeSession{
		recvCh:  make(chan []byte, 8),
		sendCh:  make(chan []byte, 8),
		closeCh: make(chan struct{}),
	}
	ns, err := cip.NewNetstack(context.Background(), sess, cip.NetstackOptions{
		LocalIPv4: netip.MustParseAddr("198.18.0.2"),
		LocalIPv6: netip.MustParseAddr("fd00::2"),
	})
	if err != nil {
		t.Fatalf("create netstack: %v", err)
	}
	defer ns.Close()

	s := &coreSession{}
	s.UDPHTTPLayer.Store(option.MasqueHTTPLayerH3)
	s.IngressTCPNetstack.Store(ns)

	if !s.deliverConnectIPTCPIngressNoFlush(pkt) {
		t.Fatal("expected TCP ingress deliver")
	}
	s.flushConnectIPIngressAckWake()
	if s.ConnectIPIngressAckWake.Pending() {
		t.Fatal("wake must be flushed after deliver on H3")
	}
}

func TestConnectIPIngressAckWakeNilHTTPConnSafe(t *testing.T) {
	t.Parallel()
	pkt := buildIngressBridgeTestACK(t)

	s := &coreSession{}
	s.UDPHTTPLayer.Store(option.MasqueHTTPLayerH3)
	s.IPHTTPConn = nil

	s.noteConnectIPIngressAckForWake(pkt)
	s.flushConnectIPIngressAckWake()
	if s.ConnectIPIngressAckWake.Pending() {
		t.Fatal("nil IPHTTPConn must consume pending wake without leaving it set")
	}
}

func TestConnectIPIngressAckWakeH2SkipsMasqueWake(t *testing.T) {
	t.Parallel()
	pkt := buildIngressBridgeTestACK(t)

	s := &coreSession{}
	s.UDPHTTPLayer.Store(option.MasqueHTTPLayerH2)
	s.IPHTTPConn = &http3.ClientConn{}

	s.noteConnectIPIngressAckForWake(pkt)
	if !s.ConnectIPIngressAckWake.Pending() {
		t.Fatal("expected pending wake before flush")
	}
	s.flushConnectIPIngressAckWake()
	if s.ConnectIPIngressAckWake.Pending() {
		t.Fatal("H2 overlay must consume wake without leaving pending")
	}
}

func TestConnectIPIngressAckWakeH2MockUploadFullLoop(t *testing.T) {
	t.Parallel()
	pkt := buildIngressBridgeTestACK(t)

	sess := &packetPipeSession{
		recvCh:  make(chan []byte, 8),
		sendCh:  make(chan []byte, 8),
		closeCh: make(chan struct{}),
	}
	ns, err := cip.NewNetstack(context.Background(), sess, cip.NetstackOptions{
		LocalIPv4: netip.MustParseAddr("198.18.0.2"),
		LocalIPv6: netip.MustParseAddr("fd00::2"),
	})
	if err != nil {
		t.Fatalf("create netstack: %v", err)
	}
	defer ns.Close()

	upload := &h2IngressUploadFlushStub{}
	s := &coreSession{}
	s.UDPHTTPLayer.Store(option.MasqueHTTPLayerH2)
	s.IPHTTPH2Upload = upload
	s.IngressTCPNetstack.Store(ns)

	if !s.deliverConnectIPTCPIngressNoFlush(pkt) {
		t.Fatal("expected TCP ingress deliver")
	}
	s.flushConnectIPIngressAckWake()
	if upload.flushCalls != 1 {
		t.Fatalf("H2 full ingress loop must flush upload once, got %d", upload.flushCalls)
	}
	if s.ConnectIPIngressAckWake.Pending() {
		t.Fatal("wake must be flushed after deliver on H2")
	}
}

type h2IngressUploadFlushStub struct {
	flushCalls int
}

func (s *h2IngressUploadFlushStub) Write(p []byte) (int, error) {
	return len(p), nil
}

func (s *h2IngressUploadFlushStub) Flush() error {
	s.flushCalls++
	return nil
}

func TestConnectIPIngressAckWakeH3MockClientConnFullLoop(t *testing.T) {
	t.Parallel()
	pkt := buildIngressBridgeTestACK(t)

	sess := &packetPipeSession{
		recvCh:  make(chan []byte, 8),
		sendCh:  make(chan []byte, 8),
		closeCh: make(chan struct{}),
	}
	ns, err := cip.NewNetstack(context.Background(), sess, cip.NetstackOptions{
		LocalIPv4: netip.MustParseAddr("198.18.0.2"),
		LocalIPv6: netip.MustParseAddr("fd00::2"),
	})
	if err != nil {
		t.Fatalf("create netstack: %v", err)
	}
	defer ns.Close()

	wake := &h3WakeSenderStub{}
	s := &coreSession{}
	s.UDPHTTPLayer.Store(option.MasqueHTTPLayerH3)
	s.IngressTCPNetstack.Store(ns)
	s.connectIPAckWakeSender = wake

	if !s.deliverConnectIPTCPIngressNoFlush(pkt) {
		t.Fatal("expected TCP ingress deliver")
	}
	s.flushConnectIPIngressAckWake()
	if wake.calls != 1 {
		t.Fatalf("H3 full ingress loop must MasqueWakeSend once, got %d", wake.calls)
	}
	if s.ConnectIPIngressAckWake.Pending() {
		t.Fatal("wake must be flushed after deliver on H3")
	}
}

type h3WakeSenderStub struct {
	calls int
}

func (s *h3WakeSenderStub) MasqueWakeSend() {
	s.calls++
}

func buildIngressBridgeTestACK(t *testing.T) []byte {
	t.Helper()
	ihl := 20
	doff := int(header.TCPMinimumSize)
	pkt := make([]byte, ihl+doff)
	pkt[0] = 0x45
	pkt[9] = byte(header.TCPProtocolNumber)
	pkt[ihl+12] = 0x50
	pkt[ihl+13] = 0x10
	return pkt
}

func TestIngressTCPNetstackForInjectUnderOpenDialMu(t *testing.T) {
	t.Parallel()
	sess := &packetPipeSession{
		recvCh:  make(chan []byte, 8),
		sendCh:  make(chan []byte, 8),
		closeCh: make(chan struct{}),
	}
	ns, err := cip.NewNetstack(context.Background(), sess, cip.NetstackOptions{
		LocalIPv4: netip.MustParseAddr("198.18.0.2"),
		LocalIPv6: netip.MustParseAddr("fd00::2"),
	})
	if err != nil {
		t.Fatalf("create netstack: %v", err)
	}
	defer ns.Close()

	s := &coreSession{}
	s.IngressTCPNetstack.Store(ns)
	s.Mu.Lock()
	host := connectIPIngressHost{s: s}
	if got := host.IngressTCPNetstackForInject(); got != ns {
		t.Fatalf("ForInject=%p want %p while Mu held (open-dial stall regression)", got, ns)
	}
	s.Mu.Unlock()
}
