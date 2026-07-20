//go:build masque_inttest_heavy

package inttest

// Conn-wire harness: H2 dial → ClientPacketSession only (no netstack/ingress).
// UDP fountain S2C benches ReadPacket throughput independent of gVisor TCP stack.

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	connectipgo "github.com/quic-go/connect-ip-go"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/sagernet/sing-box/transport/masque"
	"github.com/sagernet/sing-box/transport/masque/connectip"
	cipframe "github.com/sagernet/sing-box/transport/masque/connectip/frame"
	ciph2 "github.com/sagernet/sing-box/transport/masque/connectip/h2"
	h2c "github.com/sagernet/sing-box/transport/masque/h2"
)

const (
	connWireUDPFountainPayloadLen = 512
	connWireUDPSrcPort            = 49152
)

type connectIPConnWireStack struct {
	raw   *connectipgo.Conn
	conn  *connectip.ClientPacketSession
	wake  func()
	cancel context.CancelFunc
}

// ingressWireSample adds H2 stream DATAGRAM ingress drop attribution to a wire sample.
type ingressWireSample struct {
	ThroughputSample
	IngressDrops uint64
}

func snapshotIngressDrops() uint64 {
	return connectipgo.StreamCapsuleDatagramIngressDropTotal()
}

func runL1DownloadWithS2CStats(tb testing.TB, stack *connectIPL1Stack, layer string, dur time.Duration) connWireS2CResult {
	tb.Helper()
	connectipgo.ResetH2S2CStats()
	client := runL1DownloadSample(tb, stack, layer, dur)
	return connWireS2CResult{
		Client:              client,
		ServerDatagramBytes: connectipgo.H2S2CDatagramBytesTotal(),
		ServerDatagrams:     connectipgo.H2S2CDatagramSentTotal(),
		ServerFlushes:       connectipgo.H2S2CFlushTotal(),
		ServerFlushSkips:    connectipgo.H2S2CFlushSkipTotal(),
		ServerIdleFlushes:   connectipgo.H2S2CIdleFlushTotal(),
		ServerFlushNsTotal:  connectipgo.H2S2CFlushNsTotal(),
	}
}

func runL1DownloadWithIngressDrops(tb testing.TB, stack *connectIPL1Stack, layer string, dur time.Duration) ingressWireSample {
	tb.Helper()
	connectipgo.ResetStreamCapsuleDatagramIngressDropTotal()
	sample := runL1DownloadSample(tb, stack, layer, dur)
	return ingressWireSample{
		ThroughputSample: sample,
		IngressDrops:     snapshotIngressDrops(),
	}
}

func runConnWireUDPFountainWithIngressDrops(tb testing.TB, stack *connectIPConnWireStack, layer string, dur time.Duration, udpPayloadLen int) ingressWireSample {
	tb.Helper()
	connectipgo.ResetStreamCapsuleDatagramIngressDropTotal()
	sample := runConnWireUDPFountainSample(tb, stack, layer, dur, udpPayloadLen)
	return ingressWireSample{
		ThroughputSample: sample,
		IngressDrops:     snapshotIngressDrops(),
	}
}

func (s ingressWireSample) StringExtra() string {
	return fmt.Sprintf("%s ingress_drops=%d", s.ThroughputSample, s.IngressDrops)
}

func (s *connectIPConnWireStack) Close() {
	if s.raw != nil {
		_ = s.raw.Close()
	}
	if s.cancel != nil {
		s.cancel()
	}
}

func openConnectIPH2ConnWire(tb testing.TB) *connectIPConnWireStack {
	tb.Helper()
	proxyPort := StartNativeConnectIPH2Server(tb)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)

	tlsCfg := h2c.ClientTLSConfig(&tls.Config{InsecureSkipVerify: true}, "127.0.0.1")
	tr, err := h2c.NewClientTransport(h2c.ClientDialConfig{
		TLSConfig:          tlsCfg,
		DialHostCandidates: []string{"127.0.0.1"},
		TCPDial: func(dialCtx context.Context, network, addr string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(dialCtx, network, addr)
		},
	})
	if err != nil {
		cancel()
		tb.Fatalf("h2 transport: %v", err)
	}
	template := mustConnectIPTemplate(tb, proxyPort)
	rawConn, err := ciph2.DialH2TunnelWithBootstrap(
		ctx,
		tr,
		template,
		connectip.H2DialParams{},
		connectip.NewSessionBootstrapParams("", "", NativeProfileLocalIPv4, ""),
	)
	if err != nil {
		cancel()
		tb.Fatalf("h2 dial: %v", err)
	}

	wake := func() { h2c.FlushConnectIPIngressAckWake(nil) }
	pktSess := connectip.NewClientPacketSessionFromParams(connectip.SessionPacketParams{
		Conn:              rawConn,
		ProfileLocalIPv4:  NativeProfileLocalIPv4,
		OverlayH2:         true,
		WakeAfterDatagram: wake,
	})

	stack := &connectIPConnWireStack{
		raw:    rawConn,
		conn:   pktSess,
		wake:   wake,
		cancel: cancel,
	}
	tb.Cleanup(func() { stack.Close() })
	return stack
}

func openConnectIPH3ConnWire(tb testing.TB) *connectIPConnWireStack {
	tb.Helper()
	proxyPort := StartNativeConnectIPH3Server(tb)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)

	tlsConf := &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{http3.NextProtoH3},
		ServerName:         "127.0.0.1",
	}
	quicCfg := masque.MasqueHTTPServerQUICConfig()
	tr := &http3.Transport{
		EnableDatagrams:    true,
		DisableCompression: true,
		TLSClientConfig:    tlsConf,
		Dial: func(dialCtx context.Context, addr string, tlsCfg *tls.Config, cfg *quic.Config) (*quic.Conn, error) {
			if cfg == nil {
				cfg = quicCfg
			}
			return quic.DialAddr(dialCtx, addr, tlsCfg, cfg)
		},
	}
	tb.Cleanup(func() { tr.Close() })
	target := fmt.Sprintf("127.0.0.1:%d", proxyPort)
	quicConn, err := tr.Dial(ctx, target, tlsConf, quicCfg)
	if err != nil {
		cancel()
		tb.Fatalf("h3 quic dial: %v", err)
	}
	template := mustConnectIPTemplate(tb, proxyPort)
	rawConn, err := connectip.DialH3TunnelWithBootstrap(
		ctx,
		tr.NewClientConn(quicConn),
		template,
		connectip.H3DialParams{},
		connectip.NewSessionBootstrapParams("", "", NativeProfileLocalIPv4, ""),
	)
	if err != nil {
		cancel()
		tb.Fatalf("h3 connect-ip dial: %v", err)
	}

	wake := func() { rawConn.FlushOutgoingDatagramSend() }
	pktSess := connectip.NewClientPacketSessionFromParams(connectip.SessionPacketParams{
		Conn:              rawConn,
		ProfileLocalIPv4:  NativeProfileLocalIPv4,
		OverlayH2:         false,
		WakeAfterDatagram: wake,
	})

	stack := &connectIPConnWireStack{
		raw:    rawConn,
		conn:   pktSess,
		wake:   wake,
		cancel: cancel,
	}
	tb.Cleanup(func() { stack.Close() })
	return stack
}

func startUDPFountain(tb testing.TB, addr *net.UDPAddr, payloadLen int) *net.UDPConn {
	tb.Helper()
	if payloadLen <= 0 {
		payloadLen = connWireUDPFountainPayloadLen
	}
	c, err := net.ListenUDP("udp", addr)
	if err != nil {
		tb.Fatalf("listen udp fountain: %v", err)
	}
	tb.Cleanup(func() { _ = c.Close() })
	payload := make([]byte, payloadLen)
	var primed atomic.Bool
	go func() {
		buf := make([]byte, 2048)
		for {
			n, raddr, err := c.ReadFrom(buf)
			if err != nil {
				return
			}
			if !primed.CompareAndSwap(false, true) {
				continue
			}
			go udpFountainFlood(c, raddr, payload)
			_ = n
		}
	}()
	return c
}

func udpFountainFlood(c *net.UDPConn, dest net.Addr, payload []byte) {
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := c.WriteTo(payload, dest); err != nil {
			return
		}
	}
}

// connWireS2CResult pairs client ReadPacket sample with server H2 S2C counters.
type connWireS2CResult struct {
	Client              ThroughputSample
	ServerDatagramBytes uint64
	ServerDatagrams     uint64
	ServerFlushes       uint64
	ServerFlushSkips    uint64
	ServerIdleFlushes   uint64
	ServerFlushNsTotal  uint64
}

func runConnWireUDPFountainWithS2CStats(tb testing.TB, stack *connectIPConnWireStack, layer string, dur time.Duration, udpPayloadLen int) connWireS2CResult {
	tb.Helper()
	connectipgo.ResetH2S2CStats()
	client := runConnWireUDPFountainSample(tb, stack, layer, dur, udpPayloadLen)
	return connWireS2CResult{
		Client:              client,
		ServerDatagramBytes: connectipgo.H2S2CDatagramBytesTotal(),
		ServerDatagrams:     connectipgo.H2S2CDatagramSentTotal(),
		ServerFlushes:       connectipgo.H2S2CFlushTotal(),
		ServerFlushSkips:    connectipgo.H2S2CFlushSkipTotal(),
		ServerIdleFlushes:   connectipgo.H2S2CIdleFlushTotal(),
		ServerFlushNsTotal:  connectipgo.H2S2CFlushNsTotal(),
	}
}

func runOnwardDirectDownloadSample(tb testing.TB, dur time.Duration) ThroughputSample {
	tb.Helper()
	downloadLn := StartNativeConnectIPDownloadTarget(tb)
	addr := downloadLn.Addr().(*net.TCPAddr)
	conn, err := net.Dial("tcp", net.JoinHostPort("127.0.0.1", fmt.Sprintf("%d", addr.Port)))
	if err != nil {
		tb.Fatalf("onward direct dial: %v", err)
	}
	defer conn.Close()
	masque.PrimeNativeTCPDownload(conn)
	return measureDownloadSample("onward", "direct-tcp", conn, dur)
}

func runConnWireUDPFountainSample(tb testing.TB, stack *connectIPConnWireStack, layer string, dur time.Duration, udpPayloadLen int) ThroughputSample {
	tb.Helper()
	fountain := startUDPFountain(tb, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0}, udpPayloadLen)
	fountainAddr := fountain.LocalAddr().(*net.UDPAddr)

	src := netip.MustParseAddr(NativeProfileLocalIPv4)
	dst := netip.MustParseAddr("127.0.0.1")
	probe, err := cipframe.BuildIPv4UDPPacket(
		src, connWireUDPSrcPort, dst, uint16(fountainAddr.Port), []byte("p"),
	)
	if err != nil {
		tb.Fatalf("%s conn-wire probe packet: %v", layer, err)
	}
	if _, err := stack.conn.WritePacket(probe); err != nil {
		tb.Fatalf("%s conn-wire WritePacket probe: %v", layer, err)
	}
	stack.conn.FlushEgressBatch()
	if stack.wake != nil {
		stack.wake()
	}

	time.Sleep(20 * time.Millisecond)

	buf := make([]byte, 64*1024)
	start := time.Now()
	var total int64
	deadline := start.Add(dur)
	for time.Now().Before(deadline) {
		n, err := stack.conn.ReadPacket(buf)
		if err != nil {
			if time.Now().After(deadline) {
				break
			}
			continue
		}
		if n > 0 {
			total += int64(n)
		}
	}
	wall := time.Since(start)
	nsPerB := 0.0
	if total > 0 {
		nsPerB = float64(wall.Nanoseconds()) / float64(total)
	}
	mbps := 0.0
	if wall > 0 {
		mbps = float64(total*8) / wall.Seconds() / 1e6
	}
	return ThroughputSample{
		Layer:          layer,
		Leg:            fmt.Sprintf("conn-wire-udp-fountain-%dB", udpPayloadLen),
		Bytes:          total,
		Mbps:           mbps,
		Wall:           wall,
		NsPerByte:      nsPerB,
		CPUCeilingMbps: masque.SynthCPUMbpsCeiling(nsPerB),
	}
}
