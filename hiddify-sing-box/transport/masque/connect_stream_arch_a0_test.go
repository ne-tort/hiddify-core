//go:build synth_arch_a0

package masque

import (
	"context"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/transport/masque/h3"
	strm "github.com/sagernet/sing-box/transport/masque/stream"
)

// Arch investigation wave A0 — root cause code map + contention matrix (synth contracts).

// TestArchA0CodeMapConnectStreamBytePath (A0-2): iperf -R download in prod uses
// route connectionCopy writer_to → h3.TunnelConn.WriteTo → S2C DATA (reader or h3 stream).
func TestArchA0CodeMapConnectStreamBytePath(t *testing.T) {
	t.Run("prod_h3_stream_write_to_drain", func(t *testing.T) {
		h := startConnectStreamDownloadHarness(t, benchWindowedBidiLink())
		defer h.close()
		if _, ok := h.conn.(io.WriterTo); !ok {
			t.Fatal("A0-2 prod download path requires io.WriterTo on dial result")
		}
		n, mbps, err := measureTCPDownloadWriteToMbps(h.conn, localizeBenchDuration)
		if err != nil {
			t.Fatalf("A0-2 WriteTo drain: %v", err)
		}
		if n < localizeBenchMinBytes {
			t.Fatalf("A0-2 bytes=%d want >= %d", n, localizeBenchMinBytes)
		}
		tc, ok := unwrapH3TunnelConn(h.conn)
		if !ok || !tc.UsesH3Stream() {
			t.Fatal("A0-2 prod path must drain via *http3.Stream (UsesH3Stream=true)")
		}
		t.Logf("A0-2 prod WriteTo: %.1f Mbit/s (%d bytes)", mbps, n)
	})

	t.Run("prod_h3_stream_write_to", func(t *testing.T) {
		var hookActive atomic.Int32
		h3.SetTestBidiDownloadActiveHook(func(active bool) {
			if active {
				hookActive.Add(1)
			}
		})
		t.Cleanup(func() { h3.SetTestBidiDownloadActiveHook(nil) })

		h := startConnectStreamDownloadHarness(t, instantBidiLink{})
		defer h.close()
		_, _, err := measureTCPDownloadWriteToMbps(h.conn, localizeBenchDuration)
		if err != nil {
			t.Fatalf("A0-2 bidi WriteTo drain: %v", err)
		}
		if hookActive.Load() == 0 {
			t.Fatal("A0-2 prod h3_stream WriteTo must toggle downloadActive (bidi_wake path)")
		}
		tc, ok := unwrapH3TunnelConn(h.conn)
		if !ok || !tc.UsesH3Stream() {
			t.Fatal("A0-2 prod h3_stream must use coordinated *http3.Stream")
		}
		if tc.DownloadActive() {
			t.Fatal("A0-2 downloadActive must clear after WriteTo completes")
		}
	})
}

// TestArchA0WireVsAppPipePath (A0-1a): P1 prod h3_stream vs legacy pipe — same RFC 9114 CONNECT,
// UsesH3Stream=true (nil Body) vs UsesH3Stream=false (io.Pipe upload).
func TestArchA0WireVsAppPipePath(t *testing.T) {
	t.Run("prod_h3_stream_one_http3_stream", func(t *testing.T) {
		h := startConnectStreamDownloadHarness(t, instantBidiLink{})
		defer h.close()
		tc, ok := unwrapH3TunnelConn(h.conn)
		if !ok {
			t.Fatal("expected *h3.TunnelConn")
		}
		if !tc.UsesH3Stream() {
			t.Fatal("prod h3_stream must share one http3.Stream (UsesH3Stream=true)")
		}
		if !strm.ProdDialShapeOf(h.conn).OK() {
			t.Fatal("prod h3_stream dial must satisfy prod route shape")
		}
	})

	t.Run("legacy_pipe_same_connect_different_halves", func(t *testing.T) {
		h := startConnectStreamDownloadHarness(t, instantBidiLink{})
		defer h.close()
		tc, ok := unwrapH3TunnelConn(h.conn)
		if !ok {
			t.Fatal("expected *h3.TunnelConn")
		}
		if tc.UsesH3Stream() {
			t.Fatal("legacy pipe upload must decouple upload half (UsesH3Stream=false)")
		}
		if !strm.ProdDialShapeOf(h.conn).OK() {
			t.Fatal("legacy pipe dial must still satisfy prod route shape on one net.Conn")
		}
	})
}

// TestArchA0ContentionPointsContract (A0-2a): documents known contention anchors —
// H3BidiBootstrapUploadBytes, H3UploadFlushChunkBytes, TunnelWriteToBufLen, 64 KiB bidi window model.
func TestArchA0ContentionPointsContract(t *testing.T) {
	const wantBootstrapUpload = 4 * 1024
	const wantUploadFlushChunk = 64 * 1024
	const wantWriteToBuf = 256 * 1024
	const wantBidiWindow = 64 * 1024

	if got := h3.H3BidiBootstrapUploadBytes; got != wantBootstrapUpload {
		t.Fatalf("A0-2a bidi bootstrap upload: %d want %d", got, wantBootstrapUpload)
	}
	if got := h3.H3UploadFlushChunkBytes; got != wantUploadFlushChunk {
		t.Fatalf("A0-2a upload flush chunk: %d want %d", got, wantUploadFlushChunk)
	}
	if h3.DefaultBidiWindowSizeBytes != wantBidiWindow {
		t.Fatalf("A0-2a bidi window model: %d want %d", h3.DefaultBidiWindowSizeBytes, wantBidiWindow)
	}
	if h3.TunnelWriteToBufLen != wantWriteToBuf {
		t.Fatalf("A0-2a WriteTo drain buf: %d want %d", h3.TunnelWriteToBufLen, wantWriteToBuf)
	}

	t.Setenv("MASQUE_CONNECT_STREAM_PIPE_UPLOAD", "0")

	h := startConnectStreamDownloadHarness(t, instantBidiLink{})
	defer h.close()
	tc, ok := unwrapH3TunnelConn(h.conn)
	if !ok || !tc.UsesH3Stream() {
		t.Fatal("A0-2a prod h3_stream path must use *http3.Stream (UsesH3Stream=true)")
	}
	t.Logf("A0-2a contention anchors: bootstrapUpload=%d flushChunk=%d writeToBuf=%d bidiWindow=%d prod_h3_stream=on",
		wantBootstrapUpload, wantUploadFlushChunk, wantWriteToBuf, wantBidiWindow)
}

// TestArchA0ContentionMatrixC2SDuringS2C (A0-3): who writes C2S while S2C WriteTo drains.
func TestArchA0ContentionMatrixC2SDuringS2C(t *testing.T) {
	t.Run("prod_h3_stream_c2s_contends_on_same_stream", func(t *testing.T) {
		h := startConnectStreamDownloadHarness(t, benchWindowedBidiLink())
		defer h.close()
		tc, ok := unwrapH3TunnelConn(h.conn)
		if !ok || !tc.UsesH3Stream() {
			t.Fatal("prod h3_stream matrix row requires UsesH3Stream=true")
		}
		upMbps := runConnectStreamConcurrentUploadMbps(t, h.conn, localizeBenchDuration)
		t.Logf("A0-3 prod h3_stream C2S during S2C WriteTo (windowed): %.1f Mbit/s upload", upMbps)
		// Same-stream C2S contends with S2C credit — upload stays in wire ceiling band.
		if upMbps > connectStreamLocalizeCeilingMax+5 {
			t.Fatalf("prod h3_stream upload %.1f unexpectedly high on windowed link — C2S should contend with S2C drain", upMbps)
		}
	})

	t.Run("legacy_pipe_c2s_off_h3_stream", func(t *testing.T) {
		h := startConnectStreamDownloadHarness(t, instantBidiLink{})
		defer h.close()
		tc, ok := unwrapH3TunnelConn(h.conn)
		if !ok || tc.UsesH3Stream() {
			t.Fatal("legacy pipe matrix row requires UsesH3Stream=false")
		}
		upMbps := runConnectStreamConcurrentUploadMbps(t, h.conn, localizeBenchDuration)
		t.Logf("A0-3 legacy pipe C2S during S2C WriteTo: %.1f Mbit/s upload", upMbps)
		if upMbps < connectStreamLocalizeCeilingMin {
			t.Fatalf("legacy pipe upload stalled under concurrent WriteTo: %.1f Mbit/s (want >= %.0f)", upMbps, connectStreamLocalizeCeilingMin)
		}
	})
}

// TestArchA0RFCConstraintTable (A0-1): frozen RFC 9114/8441/9298/9297 feasibility for P1–P6.
func TestArchA0RFCConstraintTable(t *testing.T) {
	if len(ArchRFCConstraintTable) < 7 {
		t.Fatalf("A0-1 RFC table: %d rows want >= 7", len(ArchRFCConstraintTable))
	}
	p1, ok := ArchRFCConstraintFor(ArchPatternP1PipeUpload)
	if !ok || !p1.Feasible || p1.Role != ArchRolePrimary {
		t.Fatalf("A0-1 P1: %+v", p1)
	}
	p5, ok := ArchRFCConstraintFor(ArchPatternP5DatagramACK)
	if !ok || p5.Feasible || p5.RFC9298 {
		t.Fatalf("A0-1 P5 datagram ACK must be infeasible on connect-stream: %+v", p5)
	}
	primary := ArchPrimaryPatterns()
	if len(primary) < 3 {
		t.Fatalf("A0-1 primary patterns: %v", primary)
	}
	for _, row := range ArchRFCConstraintTable {
		if !row.Feasible && row.Role == ArchRolePrimary {
			t.Fatalf("A0-1 infeasible primary: %+v", row)
		}
		if row.Role == ArchRoleReject && row.Pattern == ArchPatternP5DatagramACK && row.Feasible {
			t.Fatalf("A0-1 P5 must stay infeasible: %+v", row)
		}
	}
	t.Logf("A0-1 RFC table: %d patterns, primary/fallback=%v", len(ArchRFCConstraintTable), primary)
}

// TestArchA0OneTCPVsNTCPMatrix (A0-1b): P1 one CONNECT, P2 dual-leg composite, P6 parallel dials.
func TestArchA0OneTCPVsNTCPMatrix(t *testing.T) {
	t.Setenv("MASQUE_H3_BIDI_DUPLEX_COORD", "1")

	p1, ok := ArchTCPConnectTopologyFor(ArchPatternP1PipeUpload)
	if !ok || p1.ConnectDials != 1 || !p1.CompositeOneConn {
		t.Fatalf("A0-1b P1 topology: %+v", p1)
	}
	p2, ok := ArchTCPConnectTopologyFor(ArchPatternP2DualConnect)
	if !ok || p2.ConnectDials != 2 || !p2.CompositeOneConn {
		t.Fatalf("A0-1b P2 topology: %+v", p2)
	}
	p6, ok := ArchTCPConnectTopologyFor(ArchPatternP6Parallel)
	if !ok || p6.ConnectDials != connectStreamParallelStreams || p6.CompositeOneConn {
		t.Fatalf("A0-1b P6 topology: %+v", p6)
	}

	t.Run("P1_one_connect_one_conn", func(t *testing.T) {
		h := startConnectStreamDownloadHarness(t, instantBidiLink{})
		defer h.close()
		if !strm.ProdDialShapeOf(h.conn).OK() {
			t.Fatal("P1 dial must expose single composite net.Conn to route")
		}
		tc, ok := unwrapH3TunnelConn(h.conn)
		if !ok || !tc.UsesH3Stream() {
			t.Fatal("prod single-bidi must use one http3.Stream")
		}
	})

	t.Run("P2_removed_dual_connect", func(t *testing.T) {
		t.Skip("P2 dual CONNECT removed — prod is single-bidi Invisv path")
	})

	t.Run("P6_parallel_n_conns", func(t *testing.T) {
		pool := startConnectStreamParallelPool(t, instantBidiLink{})
		defer pool.close()
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		defer cancel()
		seen := make(map[net.Conn]struct{})
		for i := 0; i < connectStreamParallelStreams; i++ {
			conn, err := pool.dial(ctx)
			if err != nil {
				t.Fatalf("P6 dial %d: %v", i, err)
			}
			if !strm.ProdDialShapeOf(conn).OK() {
				t.Fatalf("P6 stream %d lacks prod dial shape", i)
			}
			seen[conn] = struct{}{}
			t.Cleanup(func() { _ = conn.Close() })
		}
		if len(seen) != connectStreamParallelStreams {
			t.Fatalf("P6 want %d distinct conns, got %d", connectStreamParallelStreams, len(seen))
		}
	})
}

// TestArchA0OrchestrationBoundary (A0-2b): route/session/stream/h3/server ownership map.
func TestArchA0OrchestrationBoundary(t *testing.T) {
	if len(ArchOrchestrationBoundaries) < 5 {
		t.Fatalf("A0-2b boundary table: %d rows want >= 5", len(ArchOrchestrationBoundaries))
	}
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	dir := wd
	var singboxRoot string
	for range 12 {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			if _, err := os.Stat(filepath.Join(dir, "route", "conn.go")); err == nil {
				singboxRoot = dir
				break
			}
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	if singboxRoot == "" {
		t.Fatal("A0-2b: hiddify-sing-box root not found")
	}
	for _, row := range ArchOrchestrationBoundaries {
		path := filepath.Join(singboxRoot, row.Pkg)
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("A0-2b owner %s pkg missing %s: %v", row.Owner, path, err)
		}
	}

	t.Setenv("MASQUE_CONNECT_STREAM_PIPE_UPLOAD", "0")
	h := startConnectStreamDownloadHarness(t, instantBidiLink{})
	defer h.close()

	// route layer consumes WriterTo markers implemented by stream/h3 dial result.
	shape := strm.ProdDialShapeOf(h.conn)
	if !shape.HasWriterTo || !shape.HasWriterToMarker || !shape.HasReaderFromMarker || !shape.OuterTunnelConn {
		t.Fatalf("A0-2b stream dial must satisfy route bulk markers: %+v", shape)
	}
	tc, ok := unwrapH3TunnelConn(h.conn)
	if !ok {
		t.Fatal("A0-2b h3.TunnelConn must sit under stream.TunnelConn wrapper")
	}
	if !tc.UsesH3Stream() {
		t.Fatal("A0-2b P1 prod path: h3_stream bidi default (UsesH3Stream=true)")
	}

	// server relay buffer is separate from client WriteTo drain (relay vs tunnel WriteTo sizes).
	if strm.RelayTunnelBufLen != h3.TunnelWriteToBufLen {
		t.Logf("A0-2b note: relay buf=%d tunnel WriteTo buf=%d (same size, different layers)",
			strm.RelayTunnelBufLen, h3.TunnelWriteToBufLen)
	}
	t.Logf("A0-2b orchestration: route→WriteTo markers; session→dial policy; stream→CONNECT; h3→byte path; server relay out-of-scope K-S")
}

// TestArchA0GoroutineDirectionBlockerTable (A0-3b): frozen goroutine × direction × blocker rows
// align with prod h3_stream vs legacy pipe dial shapes.
func TestArchA0GoroutineDirectionBlockerTable(t *testing.T) {
	if len(ArchGoroutineBlockerTable) < 10 {
		t.Fatalf("A0-3b table: %d rows want >= 10", len(ArchGoroutineBlockerTable))
	}
	for _, path := range []ArchConnectPath{
		ArchPathP1ProdH3Stream, ArchPathP1LegacyPipe, ArchPathP2DualLeg, ArchPathP6ParallelLeg,
	} {
		rows := ArchGoroutineBlockersFor(path)
		if len(rows) < 2 {
			t.Fatalf("A0-3b path %s: %d rows want >= 2", path, len(rows))
		}
	}

	prodRows := ArchGoroutineBlockersFor(ArchPathP1ProdH3Stream)
	var hasEagerOrWake bool
	for _, row := range prodRows {
		if row.Role == ArchGoRouteDownload && row.Direction == ArchDirS2C {
			if row.Blocker == "" || row.Anchor == "" {
				t.Fatalf("A0-3b prod download row incomplete: %+v", row)
			}
			if strings.Contains(row.Blocker, "eager WINDOW") || strings.Contains(row.Blocker, "WriteTo drain") {
				hasEagerOrWake = true
			}
		}
		if row.Role == ArchGoRouteUpload && row.Direction == ArchDirC2S {
			if row.Blocker == "" || row.Anchor == "" {
				t.Fatalf("A0-3b prod upload row incomplete: %+v", row)
			}
			if strings.Contains(row.Blocker, "bidi_wake") || strings.Contains(row.Blocker, "H3UploadFlushPolicy") {
				hasEagerOrWake = true
			}
		}
	}
	if !hasEagerOrWake {
		t.Fatal("A0-3b prod h3_stream must document eager WINDOW or bidi_wake on upload/download rows")
	}

	legacyRows := ArchGoroutineBlockersFor(ArchPathP1LegacyPipe)
	for _, row := range legacyRows {
		if row.Role == ArchGoRouteUpload && strings.Contains(strings.ToLower(row.Blocker), "duplex_coord") {
			t.Fatalf("A0-3b legacy pipe upload must not use duplex_coord gate: %+v", row)
		}
	}

	t.Run("prod_h3_stream_default", func(t *testing.T) {
		h := startConnectStreamDownloadHarness(t, instantBidiLink{})
		defer h.close()
		tc, ok := unwrapH3TunnelConn(h.conn)
		if !ok || !tc.UsesH3Stream() {
			t.Fatal("A0-3b prod h3_stream row requires UsesH3Stream=true")
		}
	})

	t.Logf("A0-3b goroutine table: %d rows across %d paths", len(ArchGoroutineBlockerTable), 4)
}

// TestArchA0PeerContract (A0-4): s-ui + WARP peer constraints for primary patterns.
func TestArchA0PeerContract(t *testing.T) {
	if len(ArchPeerContractTable) < 5 {
		t.Fatalf("A0-4 peer table: %d rows want >= 5", len(ArchPeerContractTable))
	}
	p1Peers := ArchPeerConstraintsFor(ArchPatternP1PipeUpload)
	if len(p1Peers) < 3 {
		t.Fatalf("A0-4 P1 peer constraints: %d want >= 3", len(p1Peers))
	}
	var suiPipe bool
	for _, row := range p1Peers {
		if row.Peer == ArchPeerSUI && row.ProdDefault {
			suiPipe = true
		}
	}
	if !suiPipe {
		t.Fatal("A0-4 s-ui must accept prod-default connect_stream relay on same authority")
	}
	p2Peers := ArchPeerConstraintsFor(ArchPatternP2DualConnect)
	if len(p2Peers) == 0 {
		t.Fatal("A0-4 P2 must document dual CONNECT peer constraint")
	}
	if note, ok := ArchRouteScopeFor(ArchPatternP2DualConnect); !ok || note.InRouteScope {
		t.Fatalf("A0-4 P2 route scope: %+v", note)
	}
	t.Logf("A0-4 peer contract: %d rows, P1=%d P2=%d", len(ArchPeerContractTable), len(p1Peers), len(p2Peers))
}

// TestArchA0RejectedPeerExperiments (A0-4a): frozen reject inventory for peer-side dead ends.
func TestArchA0RejectedPeerExperiments(t *testing.T) {
	if len(ArchRejectedPeerExperiments) < 4 {
		t.Fatalf("A0-4a inventory: %d rows want >= 4", len(ArchRejectedPeerExperiments))
	}
	var authBidi bool
	for _, row := range ArchRejectedPeerExperiments {
		if row.ID == "H-AUTH-BIDI" {
			authBidi = true
			if row.Verdict != "reject" {
				t.Fatalf("A0-4a H-AUTH-BIDI verdict: %q", row.Verdict)
			}
		}
		if row.ID == "" || row.Summary == "" {
			t.Fatalf("A0-4a incomplete row: %+v", row)
		}
	}
	if !authBidi {
		t.Fatal("A0-4a must include H-AUTH-BIDI reject")
	}
	t.Logf("A0-4a rejected peer experiments: %d entries", len(ArchRejectedPeerExperiments))
}

// TestArchA0RouteScopeOutOfPattern (A0-5): P2/P6 dial policy is session-owned; route unchanged.
func TestArchA0RouteScopeOutOfPattern(t *testing.T) {
	if len(ArchRouteScopeNotes) < 4 {
		t.Fatalf("A0-5 route scope: %d notes want >= 4", len(ArchRouteScopeNotes))
	}
	for _, id := range []ArchPatternID{ArchPatternP1PipeUpload, ArchPatternP2DualConnect, ArchPatternP6Parallel, ArchPatternP8BulkFC} {
		note, ok := ArchRouteScopeFor(id)
		if !ok {
			t.Fatalf("A0-5 missing note for %s", id)
		}
		if note.InRouteScope {
			t.Fatalf("A0-5 %s must be out of route scope: %+v", id, note)
		}
		if note.Owner == ArchLayerRoute {
			t.Fatalf("A0-5 %s owner must not be route: %+v", id, note)
		}
	}

	t.Setenv("MASQUE_H3_BIDI_DUPLEX_COORD", "1")

	t.Run("P1_route_markers_unchanged", func(t *testing.T) {
		h := startConnectStreamDownloadHarness(t, instantBidiLink{})
		defer h.close()
		if !strm.ProdDialShapeOf(h.conn).OK() {
			t.Fatal("A0-5 P1 must keep prod route dial shape without route changes")
		}
	})

	t.Run("P2_removed_dual_connect", func(t *testing.T) {
		t.Skip("P2 dual CONNECT removed — prod is single-bidi Invisv path")
	})

	t.Logf("A0-5 route ADR: dial policy session/stream/h3; route/conn.go connectionCopy unchanged")
}

// TestArchA0ServerRelayRFCMap (A0-6): RFC 9298 server relay — 1 CONNECT request = 1 bidi tunnel leg.
func TestArchA0ServerRelayRFCMap(t *testing.T) {
	if len(ArchServerRelayRFCMap) < 3 {
		t.Fatalf("A0-6 relay map: %d rows want >= 3", len(ArchServerRelayRFCMap))
	}
	if !ArchServerRelayOneConnectPerTCP() {
		t.Fatal("A0-6 invariant: every relay mode must be 1 CONNECT → 1 onward TCP")
	}

	h3, ok := ArchServerRelayRowFor(ArchRelayTunnelH3)
	if !ok || h3.QUICBidiStreams != 1 || !h3.OutOfClientKS {
		t.Fatalf("A0-6 tunnel_h3: %+v", h3)
	}
	h2, ok := ArchServerRelayRowFor(ArchRelayTunnelH2)
	if !ok || h2.QUICBidiStreams != 0 || !h2.OutOfClientKS {
		t.Fatalf("A0-6 tunnel_h2: %+v", h2)
	}
	legacy, ok := ArchServerRelayRowFor(ArchRelayLegacyFlush)
	if !ok || legacy.QUICBidiStreams != 1 || legacy.FieldKPIMbps < 14 {
		t.Fatalf("A0-6 legacy_flush: %+v", legacy)
	}

	for _, row := range ArchServerRelayRFCMap {
		if row.ConnectRequests != 1 || row.OnwardTCP != 1 {
			t.Fatalf("A0-6 1:1 CONNECT↔TCP violated: %+v", row)
		}
		if row.Anchor == "" || row.DuplexModel == "" {
			t.Fatalf("A0-6 incomplete row: %+v", row)
		}
	}

	// Code anchors: relay symbols exist under stream/ and protocol/masque/relay/.
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	dir := wd
	var singboxRoot string
	for range 12 {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			if _, err := os.Stat(filepath.Join(dir, "route", "conn.go")); err == nil {
				singboxRoot = dir
				break
			}
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	if singboxRoot == "" {
		t.Fatal("A0-6: hiddify-sing-box root not found")
	}

	relayGo, err := os.ReadFile(filepath.Join(singboxRoot, "transport", "masque", "stream", "relay.go"))
	if err != nil {
		t.Fatalf("A0-6 relay.go: %v", err)
	}
	relaySrc := string(relayGo)
	for _, sym := range []string{"RelayTCPTunnel", "relayTCPTunnelBidiStream", "RelayTunnelBufLen"} {
		if !strings.Contains(relaySrc, sym) {
			t.Fatalf("A0-6 relay.go missing %q", sym)
		}
	}

	legacyGo, err := os.ReadFile(filepath.Join(singboxRoot, "protocol", "masque", "relay", "legacy_flush.go"))
	if err != nil {
		t.Fatalf("A0-6 legacy_flush.go: %v", err)
	}
	if !strings.Contains(string(legacyGo), "TCPBidirectional") {
		t.Fatal("A0-6 legacy_flush.go must define TCPBidirectional")
	}

	t.Logf("A0-6 server relay RFC map: %d modes, client K-S out-of-scope (field ~%.1f Mbit/s)",
		len(ArchServerRelayRFCMap), h3.FieldKPIMbps)
}
