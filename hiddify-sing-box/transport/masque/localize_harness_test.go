package masque

import (
	"io"
	"math"
	"net"
	"sync/atomic"
	"testing"
	"time"

	fwd "github.com/sagernet/sing-box/transport/masque/forwarder"
	"github.com/sagernet/sing-box/transport/masque/h3"
)

// downloadCopyProbeConn counts Read vs WriteTo during io.Copy drain (S95 route branch guard).
type downloadCopyProbeConn struct {
	net.Conn
	readCalls    atomic.Int32
	writeToCalls atomic.Int32
}

func (c *downloadCopyProbeConn) Read(p []byte) (int, error) {
	c.readCalls.Add(1)
	return c.Conn.Read(p)
}

func (c *downloadCopyProbeConn) WriteTo(w io.Writer) (int64, error) {
	c.writeToCalls.Add(1)
	if wt, ok := c.Conn.(io.WriterTo); ok {
		return wt.WriteTo(w)
	}
	return io.Copy(w, c.Conn)
}

// Shared bench params for L2/L3a/L3b localize (netem 35 ms, ~64 KiB in-flight window).
const (
	localizeBenchRTT              = 35 * time.Millisecond
	localizeBenchWindowBytes      = 64 * 1024
	localizeBenchWindowL256Bytes  = 256 * 1024
	localizeBenchWindowWideBytes  = 16 << 20
	localizeBenchDuration         = 400 * time.Millisecond
	localizeBenchMinBytes         = 32 * 1024
)

type localizeBidiWakeCounters struct {
	Upload   atomic.Int64
	Download atomic.Int64
}

func (c *localizeBidiWakeCounters) NoteUploadWake()   { c.Upload.Add(1) }
func (c *localizeBidiWakeCounters) NoteDownloadWake() { c.Download.Add(1) }

// localizeInjectors wires wake/queue depth probes for connect-ip and connect-stream harnesses.
type localizeInjectors struct {
	WriteQueueMetrics  *fwd.WriteQueueMetrics
	IngressWakeFlushes *atomic.Int32
	OutboundWakeCalls  *atomic.Int32
	BidiWake           *localizeBidiWakeCounters
}

func newLocalizeInjectors() localizeInjectors {
	return localizeInjectors{
		WriteQueueMetrics:  &fwd.WriteQueueMetrics{},
		IngressWakeFlushes: &atomic.Int32{},
		OutboundWakeCalls:  &atomic.Int32{},
		BidiWake:           &localizeBidiWakeCounters{},
	}
}

func (i localizeInjectors) connectIPOpts() connectIPUploadHarnessOpts {
	return connectIPUploadHarnessOpts{
		WriteQueueMetrics:  i.WriteQueueMetrics,
		IngressWakeFlushes: i.IngressWakeFlushes,
		OutboundWakeCalls:  i.OutboundWakeCalls,
	}
}

func (i localizeInjectors) connectStreamOpts() connectStreamHarnessOpts {
	return connectStreamHarnessOpts{
		BidiWakeSink: i.BidiWake,
	}
}

func benchWindowedPacketLink() windowedPacketLink {
	return windowedPacketLink{
		rtt:         localizeBenchRTT,
		windowBytes: localizeBenchWindowBytes,
	}
}

func benchWindowedBidiLink() windowedBidiLink {
	link := windowedBidiLink{
		rtt:         localizeBenchRTT,
		windowBytes: localizeBenchWindowBytes,
	}
	if h3.DownloadEagerWindowEnabled() {
		link.instantCreditS2C = true
	}
	return link
}

func benchWindowedWideBidiLink() windowedBidiLink {
	return windowedBidiLink{
		rtt:         localizeBenchRTT,
		windowBytes: localizeBenchWindowWideBytes,
	}
}

func benchWindowedBidiLinkL256() windowedBidiLink {
	return windowedBidiLink{
		rtt:         localizeBenchRTT,
		windowBytes: localizeBenchWindowL256Bytes,
	}
}

// benchWindowedBidiLinkStrictH3 models QUIC bidi FC without prod eager S2C instant credit
// (H3-H4: no instantCreditS2C — honest asymmetry / down-ceiling gates @ 64 KiB).
func benchWindowedBidiLinkStrictH3() windowedBidiLink {
	return windowedBidiLink{
		rtt:         localizeBenchRTT,
		windowBytes: localizeBenchWindowBytes,
	}
}

// benchWindowedBidiLinkStrictH3L256 is strict H3 bidi FC at 256 KiB window (~58 Mbit/s @ 35 ms)
// without instantCreditS2C — concurrent upload can starve below KPI on HEAD.
func benchWindowedBidiLinkStrictH3L256() windowedBidiLink {
	return windowedBidiLink{
		rtt:         localizeBenchRTT,
		windowBytes: localizeBenchWindowL256Bytes,
	}
}

// benchWindowedBidiLinkH3Prod applies prod eager S2C window on strict H3 bidi link (H2 P1c parity).
func benchWindowedBidiLinkH3Prod() windowedBidiLink {
	link := benchWindowedBidiLinkStrictH3()
	if h3.DownloadEagerWindowEnabled() {
		link.instantCreditS2C = true
	}
	return link
}

// TestLocalizeHarnessBenchContract keeps L2/L3 packet and bidi models on one bench profile.
func TestLocalizeHarnessBenchContract(t *testing.T) {
	t.Parallel()
	pl := benchWindowedPacketLink()
	if pl.rtt != localizeBenchRTT || pl.windowBytes != localizeBenchWindowBytes {
		t.Fatal("windowed packet link params drift")
	}
	bl := benchWindowedBidiLink()
	if bl.rtt != localizeBenchRTT || bl.windowBytes != localizeBenchWindowBytes {
		t.Fatal("windowed bidi link params drift")
	}
	l256 := benchWindowedBidiLinkL256()
	if l256.rtt != localizeBenchRTT || l256.windowBytes != localizeBenchWindowL256Bytes {
		t.Fatal("windowed L256 bidi link params drift")
	}
	wide := benchWindowedWideBidiLink()
	if wide.rtt != localizeBenchRTT || wide.windowBytes != localizeBenchWindowWideBytes {
		t.Fatal("windowed wide bidi link params drift")
	}
	inj := newLocalizeInjectors()
	if inj.WriteQueueMetrics == nil || inj.OutboundWakeCalls == nil || inj.IngressWakeFlushes == nil {
		t.Fatal("injectors not allocated")
	}
	if inj.BidiWake == nil {
		t.Fatal("BidiWake injectors not allocated")
	}
	opts := inj.connectStreamOpts()
	if opts.BidiWakeSink != inj.BidiWake {
		t.Fatal("connectStreamOpts must alias BidiWake injectors")
	}
}

// TestLocalizeConnectStreamInjectorsContract (S41): connectStreamOpts wires BidiWakeSink for harness probes.
func TestLocalizeConnectStreamInjectorsContract(t *testing.T) {
	t.Parallel()
	inj := newLocalizeInjectors()
	opts := inj.connectStreamOpts()
	if opts.BidiWakeSink == nil {
		t.Fatal("connectStreamOpts must wire BidiWakeSink")
	}
	opts.BidiWakeSink.NoteUploadWake()
	opts.BidiWakeSink.NoteDownloadWake()
	if inj.BidiWake.Upload.Load() != 1 || inj.BidiWake.Download.Load() != 1 {
		t.Fatalf("BidiWakeSink must share counters with localizeInjectors")
	}
}

// TestLocalizeBenchMinBytesContract (S44): windowed CONNECT-stream WriteTo bench must move at least
// localizeBenchMinBytes under the shared harness profile (32 KiB / 400 ms / 35 ms RTT).
func TestLocalizeBenchMinBytesContract(t *testing.T) {
	if localizeBenchMinBytes != 32*1024 {
		t.Fatalf("localizeBenchMinBytes=%d want %d", localizeBenchMinBytes, 32*1024)
	}
	h := startConnectStreamDownloadHarness(t, benchWindowedBidiLink())
	defer h.close()
	n, mbps, err := measureTCPDownloadWriteToMbps(h.conn, localizeBenchDuration)
	if err != nil {
		t.Fatalf("windowed WriteTo download: %v", err)
	}
	if n < localizeBenchMinBytes {
		t.Fatalf("bytes=%d want >= %d (harness min contract)", n, localizeBenchMinBytes)
	}
	t.Logf("localize bench min bytes contract: %d bytes %.1f Mbit/s", n, mbps)
}

// TestSharedWindowedBidiHarnessDedupe (S65): masque harness uses h3.WrapBidiWindow (single
// windowedBidiConn impl) with io.WriterTo for prod download drain.
func TestSharedWindowedBidiHarnessDedupe(t *testing.T) {
	t.Parallel()
	srv, cli := net.Pipe()
	defer srv.Close()
	link := benchWindowedBidiLink()
	wrapped := link.wrap(cli)
	if _, ok := wrapped.(io.WriterTo); !ok {
		t.Fatal("benchWindowedBidiLink().wrap must delegate to h3.WrapBidiWindow with WriteTo")
	}
	if inner, ok := h3.BidiWindowInner(wrapped); !ok || inner != cli {
		t.Fatal("h3.BidiWindowInner must unwrap harness link")
	}
	if link.rtt != h3.DefaultBidiWindowRTT || link.windowBytes != h3.DefaultBidiWindowSizeBytes {
		t.Fatalf("harness bidi params drift: rtt=%v window=%d", link.rtt, link.windowBytes)
	}
	_ = srv // pipe kept alive for wrap(cli)
}

// TestHarnessDownloadCopyRouteWriteToBranch (S95): io.Copy(sink, conn) must invoke WriterTo
// (prod route writer_to), not conn.Read — and match direct WriteTo Mbps on windowed harness.
func TestHarnessDownloadCopyRouteWriteToBranch(t *testing.T) {
	h := startConnectStreamDownloadHarness(t, benchWindowedBidiLink())
	defer h.close()
	probe := &downloadCopyProbeConn{Conn: h.conn}
	nCopy, mbpsCopy, err := measureTCPDownloadCopyMbps(probe, localizeBenchDuration)
	if err != nil {
		t.Fatalf("io.Copy download: %v", err)
	}
	if probe.writeToCalls.Load() == 0 {
		t.Fatal("io.Copy must invoke WriterTo on MASQUE conn (route writer_to branch)")
	}
	if probe.readCalls.Load() > 0 {
		t.Fatalf("io.Copy must not use Read on WriterTo conn (readCalls=%d)", probe.readCalls.Load())
	}
	if nCopy < localizeBenchMinBytes {
		t.Fatalf("io.Copy bytes=%d want >= %d", nCopy, localizeBenchMinBytes)
	}

	h2 := startConnectStreamDownloadHarness(t, benchWindowedBidiLink())
	defer h2.close()
	nWT, mbpsWT, err := measureTCPDownloadWriteToMbps(h2.conn, localizeBenchDuration)
	if err != nil {
		t.Fatalf("WriteTo download: %v", err)
	}
	if nWT < localizeBenchMinBytes {
		t.Fatalf("WriteTo bytes=%d want >= %d", nWT, localizeBenchMinBytes)
	}

	ratio := mbpsCopy / mbpsWT
	if mbpsCopy <= connectStreamVPSKPITargetDownMbps || mbpsWT <= connectStreamVPSKPITargetDownMbps {
		t.Fatalf("io.Copy vs WriteTo must both exceed KPI: copy=%.1f writeTo=%.1f", mbpsCopy, mbpsWT)
	}
	// Separate harness dials vary under eager WINDOW — loose parity band when both >> KPI.
	if ratio < 0.25 || ratio > 4.0 {
		t.Fatalf("io.Copy vs WriteTo Mbps parity: copy=%.1f writeTo=%.1f ratio=%.2f want 0.25–4.0",
			mbpsCopy, mbpsWT, ratio)
	}
	t.Logf("harness download io.Copy route branch: %.1f Mbit/s (WriteTo=%.1f, ratio=%.2f)",
		mbpsCopy, mbpsWT, ratio)
}

// TestMeasureTCPDownloadCopyMbpsContract (S95): io.Copy drain moves bytes on WriterTo adapter.
func TestMeasureTCPDownloadCopyMbpsContract(t *testing.T) {
	t.Parallel()
	srv, cli := net.Pipe()
	defer srv.Close()
	defer cli.Close()
	go func() {
		buf := make([]byte, 64*1024)
		deadline := time.Now().Add(200 * time.Millisecond)
		for time.Now().Before(deadline) {
			if _, err := srv.Write(buf); err != nil {
				return
			}
		}
	}()

	n, mbps, err := measureTCPDownloadCopyMbps(readAsWriterTo{cli}, 80*time.Millisecond)
	if err != nil {
		t.Fatalf("io.Copy drain: %v", err)
	}
	if n < localizeBenchMinBytes {
		t.Fatalf("io.Copy bytes=%d want >= %d", n, localizeBenchMinBytes)
	}
	if mbps < connectStreamLocalizeCeilingMin {
		t.Fatalf("io.Copy mbps=%.1f too slow for sanity check", mbps)
	}
	if math.IsNaN(mbps) || math.IsInf(mbps, 0) {
		t.Fatalf("invalid mbps=%v", mbps)
	}
}
