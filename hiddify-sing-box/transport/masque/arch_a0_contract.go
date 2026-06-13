package masque

// ArchPatternID names architectural patterns from the CONNECT-stream design space (A0/A1).
type ArchPatternID string

const (
	ArchPatternP1PipeUpload  ArchPatternID = "P1"
	ArchPatternP2DualConnect ArchPatternID = "P2"
	ArchPatternP3CreditSched ArchPatternID = "P3"
	ArchPatternP4ServerACK   ArchPatternID = "P4"
	ArchPatternP5DatagramACK ArchPatternID = "P5"
	ArchPatternP6Parallel    ArchPatternID = "P6"
	ArchPatternP8BulkFC      ArchPatternID = "P8"
)

// ArchPatternRole classifies pattern intent for K-S1/K-S2 investigation.
type ArchPatternRole string

const (
	ArchRolePrimary      ArchPatternRole = "primary"
	ArchRoleFallback     ArchPatternRole = "fallback"
	ArchRoleFairnessOnly ArchPatternRole = "fairness-only"
	ArchRoleReject       ArchPatternRole = "reject"
	ArchRoleProductOnly  ArchPatternRole = "product-only"
	ArchRoleBulkFC       ArchPatternRole = "bulk-fc"
)

// ArchRFCConstraint captures RFC feasibility for one design-space pattern (A0-1).
type ArchRFCConstraint struct {
	Pattern  ArchPatternID
	RFC9114  bool // HTTP/3 (RFC 9114) CONNECT
	RFC8441  bool // Extended CONNECT (RFC 8441)
	RFC9298  bool // MASQUE connect-stream (RFC 9298)
	RFC9297  bool // MASQUE proxy (RFC 9297)
	Feasible bool
	Role     ArchPatternRole
}

// ArchRFCConstraintTable is the frozen A0-1 RFC feasibility matrix for P1–P6 (+P8 companion).
var ArchRFCConstraintTable = []ArchRFCConstraint{
	{Pattern: ArchPatternP1PipeUpload, RFC9114: true, RFC8441: true, RFC9298: true, RFC9297: true, Feasible: true, Role: ArchRolePrimary},
	{Pattern: ArchPatternP2DualConnect, RFC9114: true, RFC8441: true, RFC9298: true, RFC9297: true, Feasible: true, Role: ArchRoleFallback},
	{Pattern: ArchPatternP3CreditSched, RFC9114: true, RFC8441: true, RFC9298: true, RFC9297: true, Feasible: true, Role: ArchRoleFairnessOnly},
	{Pattern: ArchPatternP4ServerACK, RFC9114: true, RFC8441: true, RFC9298: true, RFC9297: true, Feasible: true, Role: ArchRoleReject},
	{Pattern: ArchPatternP5DatagramACK, RFC9114: true, RFC8441: true, RFC9298: false, RFC9297: false, Feasible: false, Role: ArchRoleReject},
	{Pattern: ArchPatternP6Parallel, RFC9114: true, RFC8441: true, RFC9298: true, RFC9297: true, Feasible: true, Role: ArchRoleProductOnly},
	{Pattern: ArchPatternP8BulkFC, RFC9114: true, RFC8441: true, RFC9298: true, RFC9297: true, Feasible: true, Role: ArchRoleBulkFC},
}

// ArchTCPConnectTopology describes One-TCP vs N-CONNECT dial shape per pattern (A0-1b).
type ArchTCPConnectTopology struct {
	Pattern          ArchPatternID
	TCPTargets       int  // logical onward TCP targets per user flow
	ConnectDials     int  // CONNECT-stream HTTP dials per composite flow
	CompositeOneConn bool // route sees one net.Conn (P2 DualTunnelConn) vs N (P6)
	WireStreamIDs    int  // QUIC bidi stream IDs on wire per composite flow (0 = app-pipe decoupled)
}

// ArchTCPConnectMatrix is the frozen A0-1b One-TCP vs N-TCP matrix.
var ArchTCPConnectMatrix = []ArchTCPConnectTopology{
	{Pattern: ArchPatternP1PipeUpload, TCPTargets: 1, ConnectDials: 1, CompositeOneConn: true, WireStreamIDs: 1},
	{Pattern: ArchPatternP2DualConnect, TCPTargets: 1, ConnectDials: 2, CompositeOneConn: true, WireStreamIDs: 2},
	{Pattern: ArchPatternP6Parallel, TCPTargets: 1, ConnectDials: 4, CompositeOneConn: false, WireStreamIDs: 4},
}

// ArchOrchestrationLayer identifies code ownership tiers for CONNECT-stream byte paths (A0-2b).
type ArchOrchestrationLayer string

const (
	ArchLayerRoute   ArchOrchestrationLayer = "route"
	ArchLayerSession ArchOrchestrationLayer = "session"
	ArchLayerStream  ArchOrchestrationLayer = "stream"
	ArchLayerH3      ArchOrchestrationLayer = "h3"
	ArchLayerServer  ArchOrchestrationLayer = "server"
)

// ArchOrchestrationBoundary documents which layer owns a CONNECT-stream concern (A0-2b).
type ArchOrchestrationBoundary struct {
	Concern string
	Owner   ArchOrchestrationLayer
	Pkg     string // repo-relative package path under hiddify-sing-box
}

// ArchOrchestrationBoundaries is the frozen A0-2b orchestration map (client K-S path).
var ArchOrchestrationBoundaries = []ArchOrchestrationBoundary{
	{Concern: "bulk download WriteTo/ReadFrom branch", Owner: ArchLayerRoute, Pkg: "route"},
	{Concern: "CONNECT-stream dial policy (pipe/dual/hop)", Owner: ArchLayerSession, Pkg: "transport/masque"},
	{Concern: "CONNECT dial + prod dial shape wrapper", Owner: ArchLayerStream, Pkg: "transport/masque/stream"},
	{Concern: "H3 tunnel byte path + duplex_coord", Owner: ArchLayerH3, Pkg: "transport/masque/h3"},
	{Concern: "server onward TCP relay (out of client K-S)", Owner: ArchLayerServer, Pkg: "transport/masque/stream"},
}

// ArchRFCConstraintFor returns the A0-1 row for pattern, or false when unknown.
func ArchRFCConstraintFor(id ArchPatternID) (ArchRFCConstraint, bool) {
	for _, row := range ArchRFCConstraintTable {
		if row.Pattern == id {
			return row, true
		}
	}
	return ArchRFCConstraint{}, false
}

// ArchTCPConnectTopologyFor returns the A0-1b row for pattern, or false when unknown.
func ArchTCPConnectTopologyFor(id ArchPatternID) (ArchTCPConnectTopology, bool) {
	for _, row := range ArchTCPConnectMatrix {
		if row.Pattern == id {
			return row, true
		}
	}
	return ArchTCPConnectTopology{}, false
}

// ArchPrimaryPatterns reports patterns marked primary or fallback (K-S1/K-S2 candidates).
func ArchPrimaryPatterns() []ArchPatternID {
	var out []ArchPatternID
	for _, row := range ArchRFCConstraintTable {
		if row.Feasible && (row.Role == ArchRolePrimary || row.Role == ArchRoleFallback || row.Role == ArchRoleBulkFC) {
			out = append(out, row.Pattern)
		}
	}
	return out
}

// ArchTrafficDirection is wire byte direction on one CONNECT-stream leg (A0-3b).
type ArchTrafficDirection string

const (
	ArchDirS2C ArchTrafficDirection = "S2C"
	ArchDirC2S ArchTrafficDirection = "C2S"
)

// ArchGoroutineRole names the goroutine tier that owns a byte path (A0-3b).
type ArchGoroutineRole string

const (
	ArchGoRouteDownload ArchGoroutineRole = "route_download_copy"
	ArchGoRouteUpload   ArchGoroutineRole = "route_upload_copy"
	ArchGoTunnelWriteTo ArchGoroutineRole = "tunnel_write_to"
	ArchGoTunnelUpload  ArchGoroutineRole = "tunnel_upload"
)

// ArchConnectPath labels prod vs rollback dial shapes within one pattern (A0-3b).
type ArchConnectPath string

const (
	ArchPathP1ProdPipe     ArchConnectPath = "P1_prod_pipe"
	ArchPathP1BidiRollback ArchConnectPath = "P1_bidi_rollback"
	ArchPathP2DualLeg      ArchConnectPath = "P2_dual_leg"
	ArchPathP6ParallelLeg  ArchConnectPath = "P6_parallel_leg"
)

// ArchGoroutineBlockerRow documents who blocks whom during iperf -R duplex (A0-3b).
type ArchGoroutineBlockerRow struct {
	Path      ArchConnectPath
	Role      ArchGoroutineRole
	Direction ArchTrafficDirection
	Blocker   string
	Anchor    string // repo-relative under transport/masque
}

// ArchGoroutineBlockerTable is the frozen A0-3b goroutine × direction × blocker map.
var ArchGoroutineBlockerTable = []ArchGoroutineBlockerRow{
	{Path: ArchPathP1ProdPipe, Role: ArchGoRouteDownload, Direction: ArchDirS2C, Blocker: "wire QUIC stream FC (windowed ~64 KiB/RTT); no duplex_coord", Anchor: "h3/tunnel_conn.go:WriteTo"},
	{Path: ArchPathP1ProdPipe, Role: ArchGoRouteUpload, Direction: ArchDirC2S, Blocker: "reqBody pipe writer FC; upload half decoupled (UsesH3Stream=false)", Anchor: "h3/tunnel_from_response.go:ConnectTunnelUsesPipeUpload"},
	{Path: ArchPathP1ProdPipe, Role: ArchGoTunnelWriteTo, Direction: ArchDirS2C, Blocker: "io.Copy reader half; upload goroutine independent", Anchor: "h3/tunnel_conn.go:WriteTo"},
	{Path: ArchPathP1BidiRollback, Role: ArchGoTunnelWriteTo, Direction: ArchDirS2C, Blocker: "QUIC stream FC on windowed bidi", Anchor: "h3/tunnel_conn.go:writeH3DownloadTo"},
	{Path: ArchPathP1BidiRollback, Role: ArchGoTunnelUpload, Direction: ArchDirC2S, Blocker: "4 KiB upload chunk + pending queue until flush", Anchor: "h3/duplex_coord.go:flushDuplexUploadLocked"},
	{Path: ArchPathP2DualLeg, Role: ArchGoRouteDownload, Direction: ArchDirS2C, Blocker: "download leg stream FC only (separate stream ID)", Anchor: "h3/dual_tunnel_conn.go:WriteTo"},
	{Path: ArchPathP2DualLeg, Role: ArchGoRouteUpload, Direction: ArchDirC2S, Blocker: "upload leg pipe writer FC (no cross-leg duplex_coord)", Anchor: "h3/dual_tunnel_conn.go:ReadFrom"},
	{Path: ArchPathP6ParallelLeg, Role: ArchGoRouteDownload, Direction: ArchDirS2C, Blocker: "per-stream FC; route sees N independent net.Conn", Anchor: "route/conn.go:connectionCopy"},
	{Path: ArchPathP6ParallelLeg, Role: ArchGoRouteUpload, Direction: ArchDirC2S, Blocker: "per-stream upload; no route fan-in", Anchor: "route/conn.go:connectionCopy"},
}

// ArchPeerID names peer classes for CONNECT-stream deployment constraints (A0-4).
type ArchPeerID string

const (
	ArchPeerSUI     ArchPeerID = "s-ui"
	ArchPeerWarp    ArchPeerID = "warp"
	ArchPeerGeneric ArchPeerID = "generic"
)

// ArchPeerConstraint captures peer-side feasibility for architectural patterns (A0-4).
type ArchPeerConstraint struct {
	Peer        ArchPeerID
	Concern     string
	Constraint  string
	Patterns    []ArchPatternID
	ProdDefault bool // true when prod dial already satisfies constraint
}

// ArchPeerContractTable is the frozen A0-4 peer contract (s-ui + WARP + generic MASQUE).
var ArchPeerContractTable = []ArchPeerConstraint{
	{Peer: ArchPeerSUI, Concern: "template_tcp connect_stream relay", Constraint: "1 CONNECT → 1 bidi TCP relay; pipe upload body accepted on same authority", Patterns: []ArchPatternID{ArchPatternP1PipeUpload, ArchPatternP8BulkFC}, ProdDefault: true},
	{Peer: ArchPeerSUI, Concern: "dual CONNECT (P2 fallback)", Constraint: "peer must allow 2 CONNECT dials to same TCP target; composite net.Conn is client-only", Patterns: []ArchPatternID{ArchPatternP2DualConnect}, ProdDefault: false},
	{Peer: ArchPeerSUI, Concern: "parallel CONNECT (P6 product)", Constraint: "N independent CONNECT dials; route fans out via N net.Conn — not K-S1 fix", Patterns: []ArchPatternID{ArchPatternP6Parallel}, ProdDefault: false},
	{Peer: ArchPeerWarp, Concern: "QUIC tuning profile", Constraint: "WarpCloudflareQUICBase min windows; BulkStreamFCFloorBytes ≥256 KiB after experimental merge", Patterns: []ArchPatternID{ArchPatternP1PipeUpload, ArchPatternP8BulkFC}, ProdDefault: true},
	{Peer: ArchPeerWarp, Concern: "connect-stream on WARP edge", Constraint: "same RFC 9298 CONNECT-stream; pipe upload decouples app path — wire FC still per direction", Patterns: []ArchPatternID{ArchPatternP1PipeUpload}, ProdDefault: true},
	{Peer: ArchPeerGeneric, Concern: "HTTPStreamer / patched quic-go", Constraint: "pipe mode requires HTTPStreamer + reqBody writer; fallback h3_pipe_up dial mode", Patterns: []ArchPatternID{ArchPatternP1PipeUpload}, ProdDefault: true},
}

// ArchRejectedPeerExperiment documents field experiments rejected for K-S1 (A0-4a).
type ArchRejectedPeerExperiment struct {
	ID      string
	Peer    ArchPeerID
	Summary string
	Verdict string // reject | merged-no-kpi
	KPIMbps float64
}

// ArchRejectedPeerExperiments is the frozen A0-4a inventory (subset tied to CONNECT-stream).
var ArchRejectedPeerExperiments = []ArchRejectedPeerExperiment{
	{ID: "H-AUTH-BIDI", Peer: ArchPeerSUI, Summary: "removed: MASQUE_CONNECT_AUTHORITY_BIDI_STREAM — prod connect_stream only", Verdict: "reject", KPIMbps: 0},
	{ID: "H-AUTH-H3-STREAM", Peer: ArchPeerSUI, Summary: "removed: MASQUE_CONNECT_AUTHORITY_H3_STREAM — prod connect_stream only", Verdict: "reject", KPIMbps: 0},
	{ID: "H-SRV-ACK16", Peer: ArchPeerSUI, Summary: "server relayUploadCopyACK 16 KiB + s-ui deploy", Verdict: "reject", KPIMbps: 14.9},
	{ID: "H-SRV-RELAY", Peer: ArchPeerSUI, Summary: "server download 512 KiB + batched flush env", Verdict: "merged-no-kpi", KPIMbps: 14.7},
	{ID: "H-THIN-SB-CLIENT", Peer: ArchPeerSUI, Summary: "thin server × sb client — sb client wrap not root cause", Verdict: "reject", KPIMbps: 554},
}

// ArchRouteScopeNote documents whether route/ must change for a pattern (A0-5 ADR).
type ArchRouteScopeNote struct {
	Pattern      ArchPatternID
	InRouteScope bool
	Owner        ArchOrchestrationLayer
	Note         string
}

// ArchRouteScopeNotes is the frozen A0-5 route out-of-scope map for P2/P6 (+ P1/P8 confirmation).
var ArchRouteScopeNotes = []ArchRouteScopeNote{
	{Pattern: ArchPatternP1PipeUpload, InRouteScope: false, Owner: ArchLayerSession, Note: "route uses existing WriterTo/ReadFrom markers; pipe dial policy in session/stream/h3"},
	{Pattern: ArchPatternP2DualConnect, InRouteScope: false, Owner: ArchLayerSession, Note: "DualTunnelConn exposes same route markers; 2× CONNECT dial is session-owned"},
	{Pattern: ArchPatternP6Parallel, InRouteScope: false, Owner: ArchLayerSession, Note: "N parallel dials product-only; route connectionCopy unchanged per conn"},
	{Pattern: ArchPatternP8BulkFC, InRouteScope: false, Owner: ArchLayerH3, Note: "FinalizeConnectStreamQUICConfig in h3; route unchanged"},
}

// ArchGoroutineBlockersFor returns A0-3b rows for one connect path.
func ArchGoroutineBlockersFor(path ArchConnectPath) []ArchGoroutineBlockerRow {
	var out []ArchGoroutineBlockerRow
	for _, row := range ArchGoroutineBlockerTable {
		if row.Path == path {
			out = append(out, row)
		}
	}
	return out
}

// ArchPeerConstraintsFor returns A0-4 rows mentioning pattern.
func ArchPeerConstraintsFor(id ArchPatternID) []ArchPeerConstraint {
	var out []ArchPeerConstraint
	for _, row := range ArchPeerContractTable {
		for _, p := range row.Patterns {
			if p == id {
				out = append(out, row)
				break
			}
		}
	}
	return out
}

// ArchRouteScopeFor returns the A0-5 note for pattern, or false when unknown.
func ArchRouteScopeFor(id ArchPatternID) (ArchRouteScopeNote, bool) {
	for _, row := range ArchRouteScopeNotes {
		if row.Pattern == id {
			return row, true
		}
	}
	return ArchRouteScopeNote{}, false
}

// ArchServerRelayMode names prod server relay paths for one CONNECT-stream request (A0-6).
type ArchServerRelayMode string

const (
	ArchRelayTunnelH3      ArchServerRelayMode = "tunnel_h3"
	ArchRelayTunnelH2      ArchServerRelayMode = "tunnel_h2"
	ArchRelayLegacyFlush   ArchServerRelayMode = "legacy_flush"
)

// ArchServerRelayRFCRow documents RFC 9298 CONNECT-stream server relay: 1 CONNECT = 1 bidi leg (A0-6).
type ArchServerRelayRFCRow struct {
	Mode            ArchServerRelayMode
	RFCRefs         string // frozen RFC citation bundle
	ConnectRequests int    // HTTP CONNECT requests per onward TCP target
	QUICBidiStreams int    // QUIC bidi stream IDs per CONNECT (0 on pure H2)
	OnwardTCP       int    // logical onward TCP sockets per CONNECT
	DuplexModel     string // C2S/S2C mapping on the relay leg
	OutOfClientKS   bool   // true when client K-S ceiling is independent of relay tuning
	FieldKPIMbps    float64
	Anchor          string // repo-relative under hiddify-sing-box
}

// ArchServerRelayRFCMap is the frozen A0-6 server relay topology (RFC 9298 §3 + 9114/8441 CONNECT).
// All modes: exactly one HTTP CONNECT request maps to one full-duplex tunnel relay.
var ArchServerRelayRFCMap = []ArchServerRelayRFCRow{
	{
		Mode: ArchRelayTunnelH3, RFCRefs: "RFC9298+RFC9114",
		ConnectRequests: 1, QUICBidiStreams: 1, OnwardTCP: 1,
		DuplexModel: "h3 hijack *http3.Stream: C2S=uploadSrc→target, S2C=target→bidi (io.CopyBuffer 64 KiB)",
		OutOfClientKS: true, FieldKPIMbps: 14.9,
		Anchor: "transport/masque/stream/relay.go:relayTCPTunnelBidiStream",
	},
	{
		Mode: ArchRelayTunnelH2, RFCRefs: "RFC9298+RFC8441",
		ConnectRequests: 1, QUICBidiStreams: 0, OnwardTCP: 1,
		DuplexModel: "EnableFullDuplex H2: C2S=reqBody→target, S2C=target→responseWriter (64 KiB io.CopyBuffer + batch flush)",
		OutOfClientKS: true, FieldKPIMbps: 14.8,
		Anchor: "transport/masque/stream/relay.go:RelayTCPTunnel",
	},
	{
		Mode: ArchRelayLegacyFlush, RFCRefs: "RFC9298",
		ConnectRequests: 1, QUICBidiStreams: 1, OnwardTCP: 1,
		DuplexModel: "TCPBidirectional per-read flush (MASQUE_RELAY_TCP_LEGACY=1); still 1 CONNECT=1 bidi",
		OutOfClientKS: true, FieldKPIMbps: 14.7,
		Anchor: "protocol/masque/relay/legacy_flush.go:TCPBidirectional",
	},
}

// ArchServerRelayRowFor returns the A0-6 row for mode, or false when unknown.
func ArchServerRelayRowFor(mode ArchServerRelayMode) (ArchServerRelayRFCRow, bool) {
	for _, row := range ArchServerRelayRFCMap {
		if row.Mode == mode {
			return row, true
		}
	}
	return ArchServerRelayRFCRow{}, false
}

// ArchServerRelayOneConnectPerTCP reports whether every row enforces 1 CONNECT → 1 onward TCP (A0-6 invariant).
func ArchServerRelayOneConnectPerTCP() bool {
	for _, row := range ArchServerRelayRFCMap {
		if row.ConnectRequests != 1 || row.OnwardTCP != 1 {
			return false
		}
	}
	return len(ArchServerRelayRFCMap) > 0
}
