//go:build masque_ref

package masque

// Isolated masque-go fork client↔server vs prod sing-box relay on prod-shaped H3 upload profile.

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"testing"
	"time"

	qmasque "github.com/quic-go/masque-go"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/sagernet/sing-box/route"
	"github.com/sagernet/sing-box/transport/masque/connectudp"
	"github.com/yosida95/uritemplate/v3"
)

const isolatedMasqueGoRealScenarioBudget = 28 * time.Second

func startMasqueGoForkProxy(t testing.TB) (port int, template *uritemplate.Template) {
	t.Helper()
	quicConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("listen quic udp: %v", err)
	}
	t.Cleanup(func() { _ = quicConn.Close() })
	port = quicConn.LocalAddr().(*net.UDPAddr).Port
	raw := fmt.Sprintf("https://127.0.0.1:%d/masque/udp/{target_host}/{target_port}", port)
	template, err = uritemplate.New(raw)
	if err != nil {
		t.Fatalf("template: %v", err)
	}
	mux := http.NewServeMux()
	proxy := &qmasque.Proxy{}
	t.Cleanup(func() { _ = proxy.Close() })
	mux.HandleFunc("/masque/udp/{target_host}/{target_port}", func(w http.ResponseWriter, r *http.Request) {
		req, err := qmasque.ParseRequest(r, template)
		if err != nil {
			var perr *qmasque.RequestParseError
			if errors.As(err, &perr) {
				w.WriteHeader(perr.HTTPStatus)
				return
			}
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		_ = proxy.Proxy(w, req)
	})
	server := http3.Server{
		TLSConfig:       connectUDPTestTLS,
		QUICConfig:      &quic.Config{EnableDatagrams: true},
		EnableDatagrams: true,
		Handler:         mux,
	}
	t.Cleanup(func() { _ = server.Close() })
	go func() { _ = server.Serve(quicConn) }()
	waitInProcessMasqueUDPProxyReady(t, port)
	return port, template
}

func newMasqueGoForkClient(t testing.TB) *qmasque.Client {
	t.Helper()
	cl := &qmasque.Client{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
			NextProtos:         []string{http3.NextProtoH3},
		},
		QUICConfig: &quic.Config{
			EnableDatagrams:   true,
			InitialPacketSize: 1350,
		},
	}
	t.Cleanup(func() { _ = cl.Close() })
	return cl
}

func dialMasqueGoForkUDP(
	t testing.TB,
	ctx context.Context,
	cl *qmasque.Client,
	tmpl *uritemplate.Template,
	sink *net.UDPAddr,
) net.PacketConn {
	t.Helper()
	target := fmt.Sprintf("%s:%d", sink.IP.String(), sink.Port)
	dialCtx, cancel := context.WithTimeout(ctx, connectUDPSynthGateWaitCtx)
	defer cancel()
	pkt, _, err := cl.DialAddr(dialCtx, tmpl, target)
	if err != nil {
		t.Fatalf("fork masque-go DialAddr: %v", err)
	}
	t.Cleanup(func() { _ = pkt.Close() })
	route.TuneUDPPacketConn(pkt)
	return pkt
}

// TestIsolatedMasqueGoForkVsProdRealScenario exercises real CONNECT-UDP H3 profiles (≤30s):
//  1. Prod DoD steady MTU (1372B @1000 Mbit/s) — same helper as TestGATEConnectUDPH3SynthProdUploadSteady.
//  2. Docker WAN paced (512B @8 Mbit/s) — fork masque-go vs prod sing-box, perf-lab parity.
func TestIsolatedMasqueGoForkVsProdRealScenario(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), isolatedMasqueGoRealScenarioBudget)
	defer cancel()
	t.Cleanup(func() {
		if d := time.Until(deadlineFromCtx(ctx)); d < 0 {
			t.Fatalf("isolated masque-go real scenario exceeded %v budget", isolatedMasqueGoRealScenarioBudget)
		}
	})

	dur := connectUDPSynthProdBenchDuration
	payloadLen := connectudp.DefaultBenchUDPPayloadLen
	wanTargetMbit := dockerBenchUDPTargetMbit
	steady := connectudp.SteadyUploadPayloadLenH3()
	dodTargetMbit := connectUDPSynthProdMinMbps

	// Phase 1: prod DoD first (cold stack — parity with GATE steady).
	steadyMbps, steadySt, err := benchConnectUDPProdProfileH3UploadZeroLossPaced(
		t, instantDatagramLink{}, dur, steady, dodTargetMbit,
	)
	if err != nil {
		t.Fatalf("prod DoD steady upload: %v", err)
	}
	t.Logf("PROD DoD steady(%dB) paced@%.0f: %.1f Mbit/s rx=%d/%d loss=%.4f%%",
		steady, dodTargetMbit, steadyMbps, steadySt.RxPkts, steadySt.SentPkts, steadySt.LossPct)
	if !steadySt.BurstZeroLossOK(steady, connectudp.DefaultBurstMinRxRatio) {
		t.Fatalf("prod steady zero-loss failed: rx=%d/%d loss=%.4f%%",
			steadySt.RxPkts, steadySt.SentPkts, steadySt.LossPct)
	}
	assertConnectUDPSynthProdMbps(t, "L4 connect-udp-h3 prod (isolated DoD)", "udp_up_steady", steadyMbps,
		"steady MTU paced zero-loss upload (GATE steady parity)")

	const forkRun = uint32(0xF0CA0010)
	const prodRun = uint32(0xF0CA0011)

	// Phase 2: fork vs prod on docker WAN paced profile (both stacks, vanilla-quic-safe payload).
	_, forkTmpl := startMasqueGoForkProxy(t)
	forkSink, forkSeq := runUDPSequencedSink(t, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0}, forkRun)
	forkAddr := forkSink.LocalAddr().(*net.UDPAddr)
	forkPkt := dialMasqueGoForkUDP(t, ctx, newMasqueGoForkClient(t), forkTmpl, forkAddr)
	forkMbps, forkSt, err := benchConnectUDPPacketUploadSequenced(
		t, forkPkt, forkAddr, forkSeq, forkRun, dur, wanTargetMbit, payloadLen, true,
	)
	if err != nil {
		t.Fatalf("fork masque-go WAN paced upload: %v", err)
	}

	prodSink, prodSeq := runUDPSequencedSink(t, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0}, prodRun)
	prodAddr := prodSink.LocalAddr().(*net.UDPAddr)
	prodPort := startInProcessMasqueUDPProxyWithRelay(t)
	prodSession, prodCtx := InttestNewConnectUDPH3Session(t, prodPort)
	prodPkt := InttestListenPacketConnectUDP(t, prodSession, prodCtx, prodAddr)
	route.TuneUDPPacketConn(prodPkt)
	prodMbps, prodSt, err := benchConnectUDPPacketUploadSequenced(
		t, prodPkt, prodAddr, prodSeq, prodRun, dur, wanTargetMbit, payloadLen, true,
	)
	if err != nil {
		t.Fatalf("prod sing-box WAN paced upload: %v", err)
	}

	t.Logf("REAL compare WAN paced upload(%dB) @%.0f Mbit/s dur=%s:", payloadLen, wanTargetMbit, dur)
	t.Logf("  fork masque-go: %.1f Mbit/s rx=%d/%d loss=%.4f%% dup=%.2f%%",
		forkMbps, forkSt.RxPkts, forkSt.SentPkts, forkSt.LossPct, forkSt.DupPct)
	t.Logf("  prod sing-box:  %.1f Mbit/s rx=%d/%d loss=%.4f%% dup=%.2f%%",
		prodMbps, prodSt.RxPkts, prodSt.SentPkts, prodSt.LossPct, prodSt.DupPct)
	t.Logf("  fork drops: c2s_udp=%d h3_send=%d h3_rcv=%d",
		qmasque.TransientUDPSendDropTotal(), qmasque.TransientHTTPDatagramSendDropTotal(), qmasque.TransientHTTPDatagramReceiveDropTotal())

	if prodSt.LossPct > connectUDPSynthMaxLossPct {
		t.Fatalf("prod WAN paced loss=%.4f%% > max %.1f%%: rx=%d/%d",
			prodSt.LossPct, connectUDPSynthMaxLossPct, prodSt.RxPkts, prodSt.SentPkts)
	}
	if forkSt.LossPct > connectUDPSynthMaxLossPct {
		t.Logf("fork WAN paced loss=%.4f%% > max %.1f%% (reference, not gated)", forkSt.LossPct, connectUDPSynthMaxLossPct)
	}
}

func deadlineFromCtx(ctx context.Context) time.Time {
	if d, ok := ctx.Deadline(); ok {
		return d
	}
	return time.Now().Add(isolatedMasqueGoRealScenarioBudget)
}
