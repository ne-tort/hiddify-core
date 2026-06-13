package masque

import strm "github.com/sagernet/sing-box/transport/masque/stream"

// ArchREFSRCH2ORow documents one h2o proxy.tunnel attribute vs sing-box server path (REF-SRC-H2O).
type ArchREFSRCH2ORow struct {
	ID       string
	H2O      string
	SB       string
	Parity   bool
	Anchor   string
	KPINote  string
	PatchRef string
}

// ArchREFSRCH2OAudit is frozen REF-SRC-H2O-1/2/3/5: h2o connect.conf vs stream/relay.go + KPI attribution.
var ArchREFSRCH2OAudit = []ArchREFSRCH2ORow{
	{
		ID: "REF-SRC-H2O-1",
		H2O: "proxy.tunnel: ON — native CONNECT multiplex (upload req + download resp on one stream)",
		SB:  "RelayTCPTunnel: 2×goroutine io.CopyBuffer (upload→target, target→hijacked H3 stream)",
		Parity: true, Anchor: "stream/relay.go:RelayTCPTunnel; docker/masque-vps-bench/h2o/connect.conf",
		KPINote: "full-duplex shape matches; windowed ~15 = client S2C FC not goroutine split",
		PatchRef: "REF2-3 interleave audit",
	},
	{
		ID: "REF-SRC-H2O-2",
		H2O: "proxy.max-buffer-size: 65536",
		SB:  "RelayTunnelBufLen=65536, RelayTunnelFlushBytes=65536",
		Parity: true, Anchor: "stream/relay.go:RelayTunnelBufLen",
		KPINote: "H2/H3 copy buffer parity; H3 hijack skips per-read HTTP flush",
		PatchRef: "REF2-1 ArchH2OParityAudit",
	},
	{
		ID: "REF-SRC-H2O-3",
		H2O: "Native tunnel: unlimited S2C credit return (no 64 KiB/RTT stall on peer mock)",
		SB:  "Same relay DATA rate; sb-peer mock emits S2C grants/RTT (REF2-2)",
		Parity: false, Anchor: "h3/bidi_window.go:WrapBidiWindow; connect_stream_arch_ref_test.go:TestArchREF2WireWindowUpdateTrace",
		KPINote: "KPI root = client WINDOW_UPDATE latency (B7 instant_credit), not server flush",
		PatchRef: "MASQUE_QUIC_DOWNLOAD_EAGER_WINDOW + WriteTo download wake",
	},
	{
		ID: "REF-SRC-H2O-4",
		H2O: "Standalone h2o listener (no box.New, no s-ui template mux)",
		SB:  "ServerEndpoint/box.New delegate → same HandleTCPConnectRequest → RelayTCPTunnel",
		Parity: true, Anchor: "protocol/masque/endpoint_server.go; ArchREFSRCServerThinAudit",
		KPINote: "endpoint wrap adds TLS/H3/datagram plane; relay entry unchanged",
		PatchRef: "REF2-5 endpoint relay path audit",
	},
	{
		ID: "REF-SRC-H2O-5-gap-1",
		H2O: "C proxy.tunnel — zero HTTP/3 responseWriter flush batching",
		SB:  "H3 hijack: io.CopyBuffer on quic.Stream (no relayTunnelFlushWriter)",
		Parity: true, Anchor: "stream/relay.go:relayTCPTunnelBidiStream",
		KPINote: "H2 path uses 64 KiB flush; prod P0 is H3",
		PatchRef: "none — already h2o-shaped on H3",
	},
	{
		ID: "REF-SRC-H2O-5-gap-2",
		H2O: "Invisv client: direct quic.Stream Read/Write after 200",
		SB:  "TunnelConn + feeder/pipe/duplex_coord on template_tcp client",
		Parity: false, Anchor: "h3/tunnel_conn.go; REF3-1 Invisv audit",
		KPINote: "sb→h2o fast proves client sufficient; gap is sb-peer wire FC when peer slow",
		PatchRef: "MASQUE_CONNECT_STREAM_THIN=1 optional; KPI fix = eager window + wake",
	},
	{
		ID: "REF-SRC-H2O-5-gap-3",
		H2O: "Peer swap: h2o-peer no S2C window cap (bypassB2)",
		SB:  "sb-peer windowed 64 KiB / 35 ms RTT credit delay",
		Parity: false, Anchor: "connect_stream_bypass_matrix_test.go:B2_no_src_window",
		KPINote: "≥3 deltas closed → client S2C eager WINDOW_UPDATE + download wake",
		PatchRef: "replace/quic-go-patched/internal/flowcontrol/masque_threshold.go",
	},
}

// ArchREFSRCH2OTunnelMultiplex returns frozen h2o tunnel buffer for cross-package audit.
func ArchREFSRCH2OTunnelMultiplex() int { return strm.RelayTunnelBufLen }
