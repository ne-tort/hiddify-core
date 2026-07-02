package masque

// Segment-localize benches: isolate CONNECT-UDP code sites (not whole-stack KPI).
// Log line: RESULT_SEGMENT site=... code=... mbps=... loss_pct=... drops=...

import (
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"testing"
	"time"

	"github.com/sagernet/sing-box/route"
	"github.com/sagernet/sing-box/transport/masque/connectudp"
	cudprelay "github.com/sagernet/sing-box/transport/masque/connectudp/relay"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	M "github.com/sagernet/sing/common/metadata"
)

// Segment site IDs map to a single code region (reference port checklist).
const (
	segmentL0LoopbackUDP       = "L0-loopback-udp"
	segmentH3ClientDirect      = "H3-client-DialH3Production"
	segmentH3SessionListen     = "H3-session-ListenPacket"
	segmentH3BidiDirect        = "H3-bidi-DialH3Production"
	segmentH2DialSession       = "H2-dialUDPOverHTTP2"
	segmentH2SessionListen     = "H2-session-ListenPacket"
	segmentH2WritePacket       = "H2-bufio-WritePacket"
	segmentH3S2CDirect         = "H3-S2C-DialH3Production"
	segmentH3S2CSession        = "H3-S2C-ListenPacket"
	segmentH2S2CDirect         = "H2-S2C-dialUDPOverHTTP2"
	segmentH2S2CSession        = "H2-S2C-ListenPacket"
)

// segmentCodeRef is the primary file touched by each site (for localize attribution).
var segmentCodeRef = map[string]string{
	segmentL0LoopbackUDP:   "kernel:UDPConn.WriteTo",
	segmentH3ClientDirect:  "connectudp/client+dial.go:DialH3Production → conn/h3.go:WriteTo",
	segmentH3SessionListen: "connectudp/client/listen.go:ListenPacket → DialH3Production (bidi)",
	segmentH3BidiDirect:    "connectudp/client+dial.go (bidi) → relay/h3.go:proxyConnSend",
	segmentH2DialSession:   "connectudp/h2/packet_conn_upload.go:writeUploadUDPPayloadUnlocked",
	segmentH2SessionListen: "session.ListenPacket → h2/asymmetric_packet_conn.go",
	segmentH2WritePacket:   "bufio.WritePacket → h2/packet_conn.go",
	segmentH3S2CDirect:     "conn/h3.go:ReadFrom ← relay/h3_s2c.go:proxyConnReceive",
	segmentH3S2CSession:    "session.ListenPacket S2C ← relay/h3_s2c.go",
	segmentH2S2CDirect:     "h2/packet_conn_downlink.go ← relay/h2_dataplane.go",
	segmentH2S2CSession:    "session.ListenPacket S2C ← h2 downlink scan",
}

// SegmentUploadResult is one upload probe at a pinned code site.
type SegmentUploadResult struct {
	Site     string
	CodeRef  string
	Mode     string
	PayloadB int
	Mbps     float64
	Stats    connectudp.SequencedStats
	Drops    connectudp.DataplaneDropSnapshot
	Relay    cudprelay.UDPRelayStatsSnapshot
}

// SegmentDownloadResult is one S2C fountain probe at a pinned code site.
type SegmentDownloadResult struct {
	Site     string
	CodeRef  string
	PayloadB int
	Mbps     float64
	Bytes    int64
	Drops    connectudp.DataplaneDropSnapshot
	Relay    cudprelay.UDPRelayStatsSnapshot
}

func segmentModeLabel(targetMbit float64) string {
	if targetMbit <= 0 {
		return "flood"
	}
	return fmt.Sprintf("paced@%.0f", targetMbit)
}

func segmentBenchDuration() time.Duration {
	return connectUDPSynthProdBenchDuration
}

func segmentPayloadLen(payloadLen int) int {
	if payloadLen <= 0 {
		return connectudp.DefaultBenchUDPPayloadLen
	}
	return payloadLen
}

func segmentEnableRelayStats(tb testing.TB) {
	tb.Helper()
	cudprelay.EnableRelayStatsForBench()
	cudprelay.ResetUDPRelayStats()
}

func logSegmentUpload(tb testing.TB, r SegmentUploadResult) {
	tb.Helper()
	tb.Logf(
		"RESULT_SEGMENT kind=upload site=%s code=%q mode=%s payload=%d mbps=%.1f loss=%.2f%% dup=%.2f%% rx=%d/%d streamQ=%d quicRcvQ=%d c2s_in=%d c2s_out=%d s2c_in=%d s2c_out=%d",
		r.Site, r.CodeRef, r.Mode, r.PayloadB, r.Mbps, r.Stats.LossPct, r.Stats.DupPct,
		r.Stats.RxPkts, r.Stats.SentPkts,
		r.Drops.StreamDatagramQueue, r.Drops.QuicDatagramRcvQueue,
		r.Relay.C2SDatagramIn, r.Relay.C2SUDPPayloadOut,
		r.Relay.S2CUDPIn, r.Relay.S2CDatagramOut,
	)
}

func logSegmentDownload(tb testing.TB, r SegmentDownloadResult) {
	tb.Helper()
	tb.Logf(
		"RESULT_SEGMENT kind=download site=%s code=%q payload=%d mbps=%.1f bytes=%d streamQ=%d s2c_in=%d s2c_out=%d s2c_drop_send=%d",
		r.Site, r.CodeRef, r.PayloadB, r.Mbps, r.Bytes,
		r.Drops.StreamDatagramQueue,
		r.Relay.S2CUDPIn, r.Relay.S2CDatagramOut, r.Relay.S2CDropSendFail,
	)
}

func runSegmentUploadSequenced(
	tb testing.TB,
	site string,
	pkt net.PacketConn,
	sinkAddr *net.UDPAddr,
	seqSink *connectudp.SequencedSink,
	runID uint32,
	targetMbit float64,
	payloadLen int,
	dropsBefore connectudp.DataplaneDropSnapshot,
	relayBefore cudprelay.UDPRelayStatsSnapshot,
) SegmentUploadResult {
	tb.Helper()
	payloadLen = segmentPayloadLen(payloadLen)
	mbps, st, err := benchConnectUDPPacketUploadSequenced(
		tb, pkt, sinkAddr, seqSink, runID, segmentBenchDuration(), targetMbit, payloadLen, targetMbit > 0,
	)
	if err != nil {
		tb.Fatalf("segment %s upload: %v", site, err)
	}
	return SegmentUploadResult{
		Site:     site,
		CodeRef:  segmentCodeRef[site],
		Mode:     segmentModeLabel(targetMbit),
		PayloadB: payloadLen,
		Mbps:     mbps,
		Stats:    st,
		Drops:    connectudp.SnapshotDataplaneDrops().Delta(dropsBefore),
		Relay:    cudprelay.SnapshotUDPRelayStats().Delta(relayBefore),
	}
}

func benchSegmentL0LoopbackUpload(
	tb testing.TB,
	runID uint32,
	targetMbit float64,
	payloadLen int,
) SegmentUploadResult {
	tb.Helper()
	segmentEnableRelayStats(tb)
	dropsBefore := connectudp.SnapshotDataplaneDrops()
	relayBefore := cudprelay.SnapshotUDPRelayStats()

	sinkConn, seqSink := runUDPSequencedSink(tb, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0}, runID)
	sinkAddr := sinkConn.LocalAddr().(*net.UDPAddr)
	client, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		tb.Fatalf("L0 listen: %v", err)
	}
	tb.Cleanup(func() { _ = client.Close() })
	return runSegmentUploadSequenced(tb, segmentL0LoopbackUDP, client, sinkAddr, seqSink, runID, targetMbit, payloadLen, dropsBefore, relayBefore)
}

func benchSegmentH3ClientDirectUpload(
	tb testing.TB,
	runID uint32,
	targetMbit float64,
	payloadLen int,
) SegmentUploadResult {
	tb.Helper()
	segmentEnableRelayStats(tb)
	dropsBefore := connectudp.SnapshotDataplaneDrops()
	relayBefore := cudprelay.SnapshotUDPRelayStats()

	sinkConn, seqSink := runUDPSequencedSink(tb, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0}, runID)
	sinkAddr := sinkConn.LocalAddr().(*net.UDPAddr)
	proxyPort := startInProcessMasqueUDPProxy(tb, func(mux *http.ServeMux, proxyPort int) {
		registerMasqueUDPProxyHandler(tb, mux, proxyPort)
	})
	target := net.JoinHostPort(sinkAddr.IP.String(), strconv.Itoa(sinkAddr.Port))
	pkt := dialH3ConnectUDPDirect(tb, proxyPort, target)
	route.TuneUDPPacketConn(pkt)
	return runSegmentUploadSequenced(tb, segmentH3ClientDirect, pkt, sinkAddr, seqSink, runID, targetMbit, payloadLen, dropsBefore, relayBefore)
}

func benchSegmentH3SessionListenUpload(
	tb testing.TB,
	runID uint32,
	targetMbit float64,
	payloadLen int,
) SegmentUploadResult {
	tb.Helper()
	segmentEnableRelayStats(tb)
	dropsBefore := connectudp.SnapshotDataplaneDrops()
	relayBefore := cudprelay.SnapshotUDPRelayStats()

	sinkConn, seqSink := runUDPSequencedSink(tb, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0}, runID)
	sinkAddr := sinkConn.LocalAddr().(*net.UDPAddr)
	pkt, _ := newConnectUDPH3ProdListenPacket(tb, M.Socksaddr{
		Addr: netip.MustParseAddr(sinkAddr.IP.String()),
		Port: uint16(sinkAddr.Port),
	})
	route.TuneUDPPacketConn(pkt)
	return runSegmentUploadSequenced(tb, segmentH3SessionListen, pkt, sinkAddr, seqSink, runID, targetMbit, payloadLen, dropsBefore, relayBefore)
}

func benchSegmentH3BidiDirectUpload(
	tb testing.TB,
	runID uint32,
	targetMbit float64,
	payloadLen int,
) SegmentUploadResult {
	tb.Helper()
	segmentEnableRelayStats(tb)
	dropsBefore := connectudp.SnapshotDataplaneDrops()
	relayBefore := cudprelay.SnapshotUDPRelayStats()

	mbps, st, err := benchConnectUDPH3DirectUploadZeroLoss(tb, segmentBenchDuration(), segmentPayloadLen(payloadLen))
	if err != nil {
		tb.Fatalf("segment %s: %v", segmentH3BidiDirect, err)
	}
	return SegmentUploadResult{
		Site:     segmentH3BidiDirect,
		CodeRef:  segmentCodeRef[segmentH3BidiDirect],
		Mode:     segmentModeLabel(targetMbit),
		PayloadB: segmentPayloadLen(payloadLen),
		Mbps:     mbps,
		Stats:    st,
		Drops:    connectudp.SnapshotDataplaneDrops().Delta(dropsBefore),
		Relay:    cudprelay.SnapshotUDPRelayStats().Delta(relayBefore),
	}
}

func benchSegmentH2DialSessionUpload(
	tb testing.TB,
	runID uint32,
	targetMbit float64,
	payloadLen int,
) SegmentUploadResult {
	tb.Helper()
	segmentEnableRelayStats(tb)
	dropsBefore := connectudp.SnapshotDataplaneDrops()
	relayBefore := cudprelay.SnapshotUDPRelayStats()

	sinkConn, seqSink := runUDPSequencedSink(tb, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0}, runID)
	sinkAddr := sinkConn.LocalAddr().(*net.UDPAddr)
	proxyPort := startInProcessH2UDPConnectProxy(tb)
	session, waitCtx := newConnectUDPProdProfileH2SessionWithLinkTB(tb, proxyPort, instantH2Link{})
	target := net.JoinHostPort(sinkAddr.IP.String(), strconv.Itoa(sinkAddr.Port))
	pkt := dialConnectUDPH2ViaSession(tb, session, waitCtx, target)
	route.TuneUDPPacketConn(pkt)
	return runSegmentUploadSequenced(tb, segmentH2DialSession, pkt, sinkAddr, seqSink, runID, targetMbit, payloadLen, dropsBefore, relayBefore)
}

func benchSegmentH2SessionListenUpload(
	tb testing.TB,
	runID uint32,
	targetMbit float64,
	payloadLen int,
) SegmentUploadResult {
	tb.Helper()
	segmentEnableRelayStats(tb)
	dropsBefore := connectudp.SnapshotDataplaneDrops()
	relayBefore := cudprelay.SnapshotUDPRelayStats()

	sinkConn, seqSink := runUDPSequencedSink(tb, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0}, runID)
	sinkAddr := sinkConn.LocalAddr().(*net.UDPAddr)
	proxyPort := startInProcessH2UDPConnectProxy(tb)
	session, waitCtx := newConnectUDPProdProfileH2SessionWithLinkTB(tb, proxyPort, instantH2Link{})
	pkt, err := session.ListenPacket(waitCtx, M.Socksaddr{
		Addr: netip.MustParseAddr(sinkAddr.IP.String()),
		Port: uint16(sinkAddr.Port),
	})
	if err != nil {
		tb.Fatalf("H2 ListenPacket: %v", err)
	}
	tb.Cleanup(func() { _ = pkt.Close() })
	route.TuneUDPPacketConn(pkt)
	return runSegmentUploadSequenced(tb, segmentH2SessionListen, pkt, sinkAddr, seqSink, runID, targetMbit, payloadLen, dropsBefore, relayBefore)
}

func benchSegmentH2WritePacketUpload(
	tb testing.TB,
	runID uint32,
	targetMbit float64,
	payloadLen int,
) SegmentUploadResult {
	tb.Helper()
	segmentEnableRelayStats(tb)
	dropsBefore := connectudp.SnapshotDataplaneDrops()
	relayBefore := cudprelay.SnapshotUDPRelayStats()

	sinkConn, seqSink := runUDPSequencedSink(tb, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0}, runID)
	sinkAddr := sinkConn.LocalAddr().(*net.UDPAddr)
	dest := M.ParseSocksaddrHostPort(sinkAddr.IP.String(), uint16(sinkAddr.Port))

	proxyPort := startInProcessH2UDPConnectProxy(tb)
	session, waitCtx := newConnectUDPProdProfileH2SessionWithLinkTB(tb, proxyPort, instantH2Link{})
	raw, err := session.ListenPacket(waitCtx, M.Socksaddr{
		Addr: netip.MustParseAddr(sinkAddr.IP.String()),
		Port: uint16(sinkAddr.Port),
	})
	if err != nil {
		tb.Fatalf("ListenPacket: %v", err)
	}
	tb.Cleanup(func() { _ = raw.Close() })
	pkt := bufio.NewPacketConn(raw)
	route.TuneUDPPacketConn(pkt)
	pw, ok := pkt.(interface {
		WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error
	})
	if !ok {
		tb.Fatal("expected WritePacket on bufio-wrapped H2 ListenPacket")
	}

	payloadLen = segmentPayloadLen(payloadLen)
	wallStart := time.Now()
	deadline := wallStart.Add(segmentBenchDuration())
	var seq uint64
	var sent int
	var paceSlot time.Time
	for time.Now().Before(deadline) {
		p := connectudp.BuildProbePayload(seq, runID, payloadLen)
		if err := writePacketWithStallGuard(tb, pkt, pw, p, dest, connectUDPSynthUploadWriteStall); err != nil {
			tb.Fatalf("writepacket segment stalled seq=%d: %v", seq, err)
		}
		sent++
		seq++
		connectudp.PaceSleepUntil(&paceSlot, payloadLen, targetMbit)
	}
	sendSec := time.Since(wallStart).Seconds()
	if sendSec <= 0 {
		sendSec = segmentBenchDuration().Seconds()
	}
	connectudp.FlushPacketConnWrites(pkt)
	_ = connectudp.DrainPacketConnUpload(pkt, connectudp.DefaultUploadDrainTimeout)
	time.Sleep(500 * time.Millisecond)
	st := seqSink.Analyze(sent, payloadLen)
	mbps := connectudp.BurstSinkGoodputMbit(st.RxPkts, payloadLen, sendSec)
	return SegmentUploadResult{
		Site:     segmentH2WritePacket,
		CodeRef:  segmentCodeRef[segmentH2WritePacket],
		Mode:     segmentModeLabel(targetMbit),
		PayloadB: payloadLen,
		Mbps:     mbps,
		Stats:    st,
		Drops:    connectudp.SnapshotDataplaneDrops().Delta(dropsBefore),
		Relay:    cudprelay.SnapshotUDPRelayStats().Delta(relayBefore),
	}
}

func runSegmentDownloadFountain(
	tb testing.TB,
	site string,
	pkt net.PacketConn,
	fountainAddr *net.UDPAddr,
	payloadLen int,
	dropsBefore connectudp.DataplaneDropSnapshot,
	relayBefore cudprelay.UDPRelayStatsSnapshot,
) SegmentDownloadResult {
	tb.Helper()
	payloadLen = segmentPayloadLen(payloadLen)
	bytes, mbps, err := benchConnectUDPPacketReceiveOnly(tb, pkt, segmentBenchDuration(), payloadLen, false)
	if err != nil {
		tb.Fatalf("segment %s download: %v", site, err)
	}
	return SegmentDownloadResult{
		Site:     site,
		CodeRef:  segmentCodeRef[site],
		PayloadB: payloadLen,
		Mbps:     mbps,
		Bytes:    bytes,
		Drops:    connectudp.SnapshotDataplaneDrops().Delta(dropsBefore),
		Relay:    cudprelay.SnapshotUDPRelayStats().Delta(relayBefore),
	}
}

func benchSegmentH3S2CDirectDownload(tb testing.TB, payloadLen int) SegmentDownloadResult {
	tb.Helper()
	segmentEnableRelayStats(tb)
	dropsBefore := connectudp.SnapshotDataplaneDrops()
	relayBefore := cudprelay.SnapshotUDPRelayStats()

	fountain := startUDPFountain(tb, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	fountainAddr := fountain.LocalAddr().(*net.UDPAddr)
	proxyPort := startInProcessMasqueUDPProxy(tb, func(mux *http.ServeMux, proxyPort int) {
		registerMasqueUDPProxyHandler(tb, mux, proxyPort)
	})
	target := net.JoinHostPort(fountainAddr.IP.String(), strconv.Itoa(fountainAddr.Port))
	pkt := dialH3ConnectUDPDirect(tb, proxyPort, target)
	route.TuneUDPPacketConn(pkt)
	if err := primeFountainReceiveBenchErr(tb, pkt, fountainAddr); err != nil {
		tb.Fatalf("prime: %v", err)
	}
	return runSegmentDownloadFountain(tb, segmentH3S2CDirect, pkt, fountainAddr, payloadLen, dropsBefore, relayBefore)
}

func benchSegmentH3S2CSessionDownload(tb testing.TB, payloadLen int) SegmentDownloadResult {
	tb.Helper()
	segmentEnableRelayStats(tb)
	dropsBefore := connectudp.SnapshotDataplaneDrops()
	relayBefore := cudprelay.SnapshotUDPRelayStats()

	fountain := startUDPFountain(tb, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	fountainAddr := fountain.LocalAddr().(*net.UDPAddr)
	pkt, _ := newConnectUDPH3ProdListenPacket(tb, M.Socksaddr{
		Addr: netip.MustParseAddr(fountainAddr.IP.String()),
		Port: uint16(fountainAddr.Port),
	})
	route.TuneUDPPacketConn(pkt)
	if err := primeFountainReceiveBenchErr(tb, pkt, fountainAddr); err != nil {
		tb.Fatalf("prime: %v", err)
	}
	return runSegmentDownloadFountain(tb, segmentH3S2CSession, pkt, fountainAddr, payloadLen, dropsBefore, relayBefore)
}

func benchSegmentH2S2CDirectDownload(tb testing.TB, payloadLen int) SegmentDownloadResult {
	tb.Helper()
	segmentEnableRelayStats(tb)
	dropsBefore := connectudp.SnapshotDataplaneDrops()
	relayBefore := cudprelay.SnapshotUDPRelayStats()

	bytes, mbps, err := benchConnectUDPH2SessionDirectDownloadFountain(tb, instantH2Link{}, segmentBenchDuration(), payloadLen)
	if err != nil {
		tb.Fatalf("segment %s: %v", segmentH2S2CDirect, err)
	}
	return SegmentDownloadResult{
		Site:     segmentH2S2CDirect,
		CodeRef:  segmentCodeRef[segmentH2S2CDirect],
		PayloadB: segmentPayloadLen(payloadLen),
		Mbps:     mbps,
		Bytes:    bytes,
		Drops:    connectudp.SnapshotDataplaneDrops().Delta(dropsBefore),
		Relay:    cudprelay.SnapshotUDPRelayStats().Delta(relayBefore),
	}
}

func benchSegmentH2S2CSessionDownload(tb testing.TB, payloadLen int) SegmentDownloadResult {
	tb.Helper()
	segmentEnableRelayStats(tb)
	dropsBefore := connectudp.SnapshotDataplaneDrops()
	relayBefore := cudprelay.SnapshotUDPRelayStats()

	fountain := startUDPFountain(tb, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	fountainAddr := fountain.LocalAddr().(*net.UDPAddr)
	proxyPort := startInProcessH2UDPConnectProxy(tb)
	session, waitCtx := newConnectUDPProdProfileH2SessionWithLinkTB(tb, proxyPort, instantH2Link{})
	pkt, err := session.ListenPacket(waitCtx, M.Socksaddr{
		Addr: netip.MustParseAddr(fountainAddr.IP.String()),
		Port: uint16(fountainAddr.Port),
	})
	if err != nil {
		tb.Fatalf("ListenPacket: %v", err)
	}
	defer func() { _ = pkt.Close() }()
	if err := primeFountainReceiveBenchErr(tb, pkt, fountainAddr); err != nil {
		tb.Fatalf("prime: %v", err)
	}
	return runSegmentDownloadFountain(tb, segmentH2S2CSession, pkt, fountainAddr, payloadLen, dropsBefore, relayBefore)
}

// segmentLossAppearsAfter compares two adjacent upload segments; returns bottleneck hint.
func segmentLossAppearsAfter(before, after SegmentUploadResult) (ratio float64, hint string) {
	if before.Stats.LossPct < 1 && after.Stats.LossPct >= 5 {
		return 0, fmt.Sprintf("loss appears crossing %s→%s (check %s)", before.Site, after.Site, after.CodeRef)
	}
	if before.Mbps <= 0 {
		return 0, ""
	}
	ratio = after.Mbps / before.Mbps
	if ratio < 0.75 && after.Mbps > 50 {
		return ratio, fmt.Sprintf("throughput cliff %s→%s ratio=%.2f (check %s)", before.Site, after.Site, ratio, after.CodeRef)
	}
	return ratio, ""
}

// segmentRelayLossSite attributes loss when relay counters diverge from sink rx.
func segmentRelayLossSite(r SegmentUploadResult) string {
	if r.Stats.SentPkts == 0 {
		return ""
	}
	if r.Relay.C2SDatagramIn > 0 && r.Relay.C2SDatagramIn < uint64(r.Stats.SentPkts) && r.Drops.StreamDatagramQueue > 0 {
		return "http3/state_tracking_stream.go:enqueueDatagramOwned + relay/h3_c2s.go:proxyConnSend drain"
	}
	if r.Relay.C2SDatagramIn > 0 && r.Relay.C2SUDPPayloadOut == r.Relay.C2SDatagramIn && r.Stats.LossPct > 1 {
		return "client/quic path before server relay (SendDatagram queue or FC)"
	}
	if r.Relay.C2SDatagramIn > 0 && r.Relay.C2SUDPPayloadOut < r.Relay.C2SDatagramIn {
		return "relay/h3_c2s_udp_writer.go:onward UDP WriteBatch"
	}
	return ""
}
