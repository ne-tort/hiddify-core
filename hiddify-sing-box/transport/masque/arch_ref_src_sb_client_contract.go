package masque

// ArchREFSRCSBClientRow documents TunnelConn vs Invisv HTTPStreamer path (REF-SRC-SB-C1).
type ArchREFSRCSBClientRow struct {
	Attr     string
	Invisv   string
	SB       string
	Parity   bool
	PatchRef string
}

// ArchREFSRCSBClientAudit is frozen REF-SRC-SB-C1: h3/tunnel_conn.go vs invisv-masque http3/client.go.
var ArchREFSRCSBClientAudit = []ArchREFSRCSBClientRow{
	{
		Attr: "After 200", Invisv: "HTTPStreamer → quic.Stream Read/Write",
		SB: "HTTPStreamer → *http3.Stream via TunnelConn", Parity: true,
	},
	{
		Attr: "Download WriteTo", Invisv: "io.Copy on stream",
		SB: "writeH3DownloadTo + per-chunk wake; eager MAX_STREAM_DATA (default on)",
		Parity: true, PatchRef: "MASQUE_QUIC_DOWNLOAD_EAGER_WINDOW + MASQUE_H3_BIDI_UPLOAD_WAKE",
	},
	{
		Attr: "Upload ReadFrom", Invisv: "io.Copy to stream",
		SB: "readFromChunked + H3UploadFlushPolicy chunks + upload wake",
		Parity: true,
	},
	{
		Attr: "feeder / pipe", Invisv: "none",
		SB: "h3_stream prod default; legacy MASQUE_CONNECT_STREAM_PIPE_UPLOAD=1", Parity: true,
	},
	{
		Attr: "duplex_coord", Invisv: "none",
		SB: "MASQUE_H3_BIDI_DUPLEX_COORD default on; off with MASQUE_CONNECT_STREAM_THIN=1",
		Parity: false, PatchRef: "thin dial for Invisv parity; prod eager window unlocks KPI without thin",
	},
}

// ArchREFSRCSBClientNonRFCRow documents non-RFC client layers (REF-SRC-SB-C2).
type ArchREFSRCSBClientNonRFCRow struct {
	Layer   string
	RFCNeed string
	Action  string // cut | keep | opt-in | synth
	Note    string
}

// ArchREFSRCSBClientNonRFC lists prototype-only client mechanisms and REF-SRC-SB-C2 verdicts.
var ArchREFSRCSBClientNonRFC = []ArchREFSRCSBClientNonRFCRow{
	{
		Layer: "pipe upload (io.Pipe req body)", RFCNeed: "no", Action: "opt-in",
		Note: "default off (h3_stream); legacy MASQUE_CONNECT_STREAM_PIPE_UPLOAD=1; P1 dead end",
	},
	{
		Layer: "feeder split (UsesH3Stream=false)", RFCNeed: "no", Action: "cut",
		Note: "pipe mode splits reader/writer off *http3.Stream; Invisv uses direct stream",
	},
	{
		Layer: "duplex_coord", RFCNeed: "no", Action: "keep",
		Note: "iperf -R interleave; off via MASQUE_CONNECT_STREAM_THIN=1 or MASQUE_H3_BIDI_DUPLEX_COORD=0",
	},
	{
		Layer: "dual CONNECT (P2)", RFCNeed: "no", Action: "opt-in",
		Note: "MASQUE_CONNECT_STREAM_DUAL_CONNECT=1 only; separate leg FC, not prod",
	},
	{
		Layer: "stream.TunnelConn wrap", RFCNeed: "yes", Action: "keep",
		Note: "error mapping + route WriterTo/ReaderFrom; not a throughput feeder",
	},
	{
		Layer: "MASQUE_QUIC_DOWNLOAD_EAGER_WINDOW", RFCNeed: "no", Action: "keep",
		Note: "default on; unlocks sb-peer K-S1/K-S2; wire contract not RFC",
	},
	{
		Layer: "H3UploadFlushPolicy chunks", RFCNeed: "no", Action: "keep",
		Note: "64 KiB upload chunks + bidi wake; minimal vs masquerade send loop",
	},
	{
		Layer: "WrapBidiWindow mock", RFCNeed: "no", Action: "synth",
		Note: "localize harness only; models sb-peer 64 KiB/RTT WINDOW_UPDATE stall",
	},
}

// ArchREFSRCSBClientC3Verdict is the frozen REF-SRC-SB-C3 peer-attribution conclusion.
const ArchREFSRCSBClientC3Verdict = "same client + h2o-peer >>21 vs sb-peer ~15 → client sufficient; root cause server/wire FC"
