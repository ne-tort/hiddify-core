//go:build masque_inttest_heavy

package inttest

// Minimal CONNECT-IP L1 stack: TLS+H2/H3 → Conn → packet session → netstack + ingress.
// No coreSession, no L3Overlay/TUN — localizes prod pipe vs full session tax.

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"testing"
	"time"

	connectipgo "github.com/quic-go/connect-ip-go"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/sagernet/sing-box/transport/masque"
	mcip "github.com/sagernet/sing-box/transport/masque/connectip"
	ciph2 "github.com/sagernet/sing-box/transport/masque/connectip/h2"
	h2c "github.com/sagernet/sing-box/transport/masque/h2"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/yosida95/uritemplate/v3"
)

type connectIPL1Stack struct {
	raw     *connectipgo.Conn
	conn    *mcip.ClientPacketSession
	ns      *mcip.Netstack
	ingress *mcip.Ingress
	cancel  context.CancelFunc
	h3Tr    *http3.Transport
}

func (s *connectIPL1Stack) Netstack() mcip.TCPNetstack { return s.ns }

func (s *connectIPL1Stack) Close() {
	if s.ingress != nil {
		s.ingress.StopGracefully()
	}
	if s.ns != nil {
		_ = s.ns.Close()
	}
	if s.raw != nil {
		_ = s.raw.Close()
	}
	if s.h3Tr != nil {
		s.h3Tr.Close()
	}
	if s.cancel != nil {
		s.cancel()
	}
}

func openConnectIPH2L1Pipe(tb testing.TB) *connectIPL1Stack {
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
		mcip.H2DialParams{},
		mcip.NewSessionBootstrapParams("", "", NativeProfileLocalIPv4, ""),
	)
	if err != nil {
		cancel()
		tb.Fatalf("h2 dial: %v", err)
	}

	stack := finishConnectIPL1Pipe(tb, ctx, cancel, rawConn, true, func() {
		h2c.FlushConnectIPIngressAckWake(nil)
	})
	tb.Cleanup(func() { stack.Close() })
	return stack
}

func openConnectIPH3L1Pipe(tb testing.TB) *connectIPL1Stack {
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
	target := fmt.Sprintf("127.0.0.1:%d", proxyPort)
	quicConn, err := tr.Dial(ctx, target, tlsConf, quicCfg)
	if err != nil {
		cancel()
		tr.Close()
		tb.Fatalf("h3 quic dial: %v", err)
	}

	template := mustConnectIPTemplate(tb, proxyPort)
	rawConn, err := mcip.DialH3TunnelWithBootstrap(
		ctx,
		tr.NewClientConn(quicConn),
		template,
		mcip.H3DialParams{},
		mcip.NewSessionBootstrapParams("", "", NativeProfileLocalIPv4, ""),
	)
	if err != nil {
		cancel()
		tr.Close()
		tb.Fatalf("h3 connect-ip dial: %v", err)
	}

	stack := finishConnectIPL1Pipe(tb, ctx, cancel, rawConn, false, func() {
		rawConn.FlushOutgoingDatagramSend()
	})
	stack.h3Tr = tr
	tb.Cleanup(func() { stack.Close() })
	return stack
}

func mustConnectIPTemplate(tb testing.TB, proxyPort int) *uritemplate.Template {
	tb.Helper()
	templateRaw := fmt.Sprintf("https://127.0.0.1:%d/masque/ip", proxyPort)
	template, err := uritemplate.New(templateRaw)
	if err != nil {
		tb.Fatalf("template: %v", err)
	}
	return template
}

func finishConnectIPL1Pipe(
	tb testing.TB,
	ctx context.Context,
	cancel context.CancelFunc,
	rawConn *connectipgo.Conn,
	overlayH2 bool,
	wakeAfterDatagram func(),
) *connectIPL1Stack {
	tb.Helper()

	pktSess := mcip.NewClientPacketSessionFromParams(mcip.SessionPacketParams{
		Conn:              rawConn,
		ProfileLocalIPv4:  NativeProfileLocalIPv4,
		OverlayH2:         overlayH2,
		WakeAfterDatagram: wakeAfterDatagram,
	})

	ns, err := mcip.NewProductionTCPNetstackFromPacketSession(ctx, pktSess)
	if err != nil {
		_ = rawConn.Close()
		cancel()
		tb.Fatalf("netstack: %v", err)
	}
	netstack, ok := ns.(*mcip.Netstack)
	if !ok {
		_ = ns.Close()
		_ = rawConn.Close()
		cancel()
		tb.Fatalf("netstack type %T", ns)
	}

	host := &l1IngressHost{
		pkt: pktSess,
		ns:  netstack,
	}
	ing := mcip.NewIngress(host)
	host.ing = ing
	ing.MaybeStart(true)

	return &connectIPL1Stack{
		raw:     rawConn,
		conn:    pktSess,
		ns:      netstack,
		ingress: ing,
		cancel:  cancel,
	}
}

func runL1DownloadSample(tb testing.TB, stack *connectIPL1Stack, layer string, dur time.Duration) ThroughputSample {
	tb.Helper()
	downloadLn := StartNativeConnectIPDownloadTarget(tb)
	downloadAddr := M.ParseSocksaddrHostPort("127.0.0.1", uint16(downloadLn.Addr().(*net.TCPAddr).Port))

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	conn, err := stack.Netstack().DialContext(ctx, downloadAddr)
	if err != nil {
		tb.Fatalf("%s l1 dial: %v", layer, err)
	}
	defer conn.Close()
	masque.PrimeNativeTCPDownload(conn)
	return measureDownloadSample(layer, "download", conn, dur)
}

// runL1DuplexDownloadSample benches download while a sibling TCP upload floods C2S on the same plane.
func runL1DuplexDownloadSample(tb testing.TB, stack *connectIPL1Stack, layer string, dur time.Duration) ThroughputSample {
	tb.Helper()
	uploadLn := masque.StartConnectIPNativeUploadSink(tb)
	downloadLn := StartNativeConnectIPDownloadTarget(tb)
	uploadAddr := M.ParseSocksaddrHostPort("127.0.0.1", uint16(uploadLn.Addr().(*net.TCPAddr).Port))
	downloadAddr := M.ParseSocksaddrHostPort("127.0.0.1", uint16(downloadLn.Addr().(*net.TCPAddr).Port))

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	upConn, err := stack.Netstack().DialContext(ctx, uploadAddr)
	if err != nil {
		tb.Fatalf("%s duplex upload dial: %v", layer, err)
	}
	downConn, err := stack.Netstack().DialContext(ctx, downloadAddr)
	if err != nil {
		_ = upConn.Close()
		tb.Fatalf("%s duplex download dial: %v", layer, err)
	}

	upDone := make(chan struct{})
	go func() {
		defer close(upDone)
		defer upConn.Close()
		_, _, _ = masque.MeasureNativeUploadMbps(upConn, dur)
	}()

	masque.PrimeNativeTCPDownload(downConn)
	sample := measureDownloadSample(layer, "download-duplex", downConn, dur)
	_ = downConn.Close()
	<-upDone
	return sample
}

type l1IngressHost struct {
	pkt     *mcip.ClientPacketSession
	ns      *mcip.Netstack
	ing     *mcip.Ingress
	ackWake bool
}

func (h *l1IngressHost) IngressTransportModeOK() bool { return h.pkt != nil }

func (h *l1IngressHost) IngressPacketReader() func(context.Context, []byte) (int, error) {
	if h.pkt == nil {
		return nil
	}
	return h.pkt.ReadPacketWithContext
}

func (h *l1IngressHost) IngressTCPInstallInflight() bool { return false }

func (h *l1IngressHost) IngressTCPNetstack() mcip.IngressNetstack { return h.ns }

func (h *l1IngressHost) IngressTCPNetstackForInject() mcip.IngressNetstack { return h.ns }

func (h *l1IngressHost) IngressTCPFastPath(pkt []byte) bool {
	return mcip.TCPIngressFastPath(pkt, true, h.ns != nil, false)
}

func (h *l1IngressHost) IngressDeliverTCPNoFlush(pkt []byte) bool {
	return mcip.DeliverTCPIngress(pkt, mcip.WireTCPIngressDeliverFromStruct(
		func() *mcip.Netstack { return h.ns },
		func() bool { return false },
		func() *mcip.Netstack { return h.ns },
		func(p []byte) {
			if h.ing != nil {
				h.ing.EnqueuePreTCP(p)
			}
		},
		func(p []byte, _ *mcip.Netstack) {
			if mcip.IPv4TCPIngressWakeCandidate(p) {
				h.ackWake = true
			}
		},
	))
}

func (h *l1IngressHost) IngressFlushAckWake() {
	if h.ackWake {
		h.ackWake = false
		if h.ns != nil {
			h.ns.ScheduleOutboundDrain()
		}
	}
}

func (h *l1IngressHost) IngressFlushEgressBatch() {
	if h.pkt != nil {
		h.pkt.FlushEgressBatch()
	}
}

func (h *l1IngressHost) IngressWritePacket() func([]byte) ([]byte, error) {
	if h.pkt == nil {
		return nil
	}
	return h.pkt.WritePacket
}

func (h *l1IngressHost) IngressOnReadFatal(error)              {}
func (h *l1IngressHost) IngressDebugLog([]byte, int, bool, bool) {}
func (h *l1IngressHost) IngressObsEvent(string)                  {}
func (h *l1IngressHost) IngressEngineDrop(string)                {}
func (h *l1IngressHost) IngressReadDrop(string)                  {}
func (h *l1IngressHost) IngressSessionReset(string)              {}
