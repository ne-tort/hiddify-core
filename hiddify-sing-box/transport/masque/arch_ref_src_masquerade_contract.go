package masque

// ArchREFSRCMasqueradeRow documents one masquerade (quiche) attribute vs sing-box CONNECT-stream.
type ArchREFSRCMasqueradeRow struct {
	ID        string
	Masq      string
	SB        string
	Parity    bool
	Anchor    string
	KPINote   string
	PatchRef  string
	PortAction string // keep | mapped | skip — REF-SRC-MASQ-3 scheduling port verdict
}

// ArchREFSRCMasqueradeAudit is frozen REF-SRC-MASQ-1/2/3: masquerade client.rs + server.rs vs sb/quic-go.
// KPI ceiling on sb-peer (~15 Mbit/s field) is client S2C WINDOW_UPDATE (REF2-2), not missing quiche retry queue.
var ArchREFSRCMasqueradeAudit = []ArchREFSRCMasqueradeRow{
	{
		ID: "REF-SRC-MASQ-1-scheduler",
		Masq: "client.rs: tokio::select — quic recv + h3 poll + http3_sender channel + 20ms retry tick",
		SB: "quic-go/http3 internal conn loop; prod WriteTo on *http3.Stream; optional duplex_coord interleave",
		Parity: false, Anchor: "repos/masquerade/src/client.rs main loop; h3/tunnel_conn.go WriteTo",
		KPINote: "explicit app loop vs runtime scheduler — not sole 15 Mbit/s cause (REF2-4, REF-SRC-SB-C3)",
		PatchRef: "none — delegate to quic-go",
		PortAction: "skip",
	},
	{
		ID: "REF-SRC-MASQ-1-stream-blocked",
		Masq: "send_body Err(StreamBlocked|Done) → http3_retry_send + interval.tick(20ms)",
		SB: "quic-go SendStream.Write blocks on writeChan until peer WINDOW_UPDATE; MasqueWake* on credit",
		Parity: true, Anchor: "quic-go-patched/send_stream.go; masquerade client.rs retry branch",
		KPINote: "quiche non-blocking send vs quic-go block-wait — semantic parity on backpressure",
		PatchRef: "replace/quic-go-patched MasqueWake + MASQUE_QUIC_DOWNLOAD_EAGER_WINDOW",
		PortAction: "mapped",
	},
	{
		ID: "REF-SRC-MASQ-1-connect-upload",
		Masq: "After 200: TCP read_half → ToSend Data → send_body in unified loop",
		SB: "CONNECT nil Body (connectNoUploadBody); upload on same bidi stream via Write/ReadFrom",
		Parity: true, Anchor: "quic-go-patched/http3/client.go; masquerade handle_http1_stream",
		KPINote: "download-only bench: no separate upload goroutine on either stack",
		PatchRef: "RFC 9114 bidi — already aligned",
		PortAction: "mapped",
	},
	{
		ID: "REF-SRC-MASQ-1-download",
		Masq: "h3 poll recv_body → connect_streams channel → TCP write_half",
		SB: "MASQUE_CONNECT_STREAM_THIN: io.CopyBuffer on stream; prod: WriteTo + eager WINDOW wake",
		Parity: true, Anchor: "h3/tunnel_conn.go WriteTo; masquerade client.rs Content::Data path",
		KPINote: "thin depth ≈ masquerade channel decouple; KPI fix = client S2C not channel shape",
		PatchRef: "MASQUE_CONNECT_STREAM_THIN=1 optional",
		PortAction: "mapped",
	},
	{
		ID: "REF-SRC-MASQ-2-connect-branch",
		Masq: "server.rs: :method CONNECT + :authority → TcpStream::connect → read_task+write_task via mpsc",
		SB: "HandleTCPConnectRequest → EnableFullDuplex → 200 → relayTCPTunnelBidiStream (2 goroutines)",
		Parity: true, Anchor: "protocol/masque/server/connect_stream.go; masquerade/server.rs CONNECT branch",
		KPINote: "tokio::join(read,write) ≡ upload+download goroutines; REF2-3 interleave OK",
		PatchRef: "REF2-4 TestArchServerH2OParityRelayL3",
		PortAction: "mapped",
	},
	{
		ID: "REF-SRC-MASQ-2-relay-shape",
		Masq: "recv_body → connect_streams channel → TCP write; TCP read → send_body + StreamBlocked retry",
		SB: "relayTunnelCopyBuffer(upload→target, target→hijacked H3); MasqueSetBidiDownloadActive on download leg",
		Parity: true, Anchor: "stream/relay.go relayTCPTunnelBidiStream; masquerade/server.rs handle_client",
		KPINote: "channel decouple ≡ goroutine decouple; server relay not K-REF-B root (K-REF-D ~14.7 same relay)",
		PatchRef: "relay_bidi_boost.go",
		PortAction: "mapped",
	},
	{
		ID: "REF-SRC-MASQ-2-response-order",
		Masq: "200 :status via http3_sender before relay tasks consume bulk DATA",
		SB: "EnableFullDuplex → WriteHeader(200) → RelayTCPTunnel (S76 wire order lock)",
		Parity: true, Anchor: "connect_stream.go; masquerade server.rs Content::Headers 200",
		KPINote: "RFC 8441 ordering preserved",
		PatchRef: "TestServerCONNECTStreamEnableFullDuplexBeforeRelay",
		PortAction: "mapped",
	},
	{
		ID: "REF-SRC-MASQ-3-verdict",
		Masq: "Rust/quiche explicit poll+retry scheduling model",
		SB: "Go-native: quic-go block-write + MasqueWake + eager WINDOW + 2-goroutine relay (no 20ms poll port)",
		Parity: true, Anchor: "arch_ref_src_masquerade_contract.go ArchMasqueradeSchedulingPortVerdict",
		KPINote: "Do not port quiche loop; field K-REF-B needs client WINDOW + server unchanged relay",
		PatchRef: "REF1-2 VPS refresh; no masquerade Rust dependency",
		PortAction: "skip",
	},
}

// ArchMasqueradeSchedulingPortVerdict is the frozen REF-SRC-MASQ-3 answer: port scheduling without Rust/quiche.
func ArchMasqueradeSchedulingPortVerdict() string {
	return "no-port: quic-go blocking send + MasqueWake + MASQUE_QUIC_DOWNLOAD_EAGER_WINDOW + relay 2-goroutine parity"
}

// archMasqueradeREF3Rows projects REF-SRC-MASQ audit into legacy REF3-2 row shape.
func archMasqueradeREF3Rows() []ArchMasqueradeThinRow {
	return []ArchMasqueradeThinRow{
		{
			Attr: "H3 scheduler",
			Masq: ArchREFSRCMasqueradeAudit[0].Masq,
			SB:   ArchREFSRCMasqueradeAudit[0].SB,
			Parity: ArchREFSRCMasqueradeAudit[0].Parity,
			Anchor: ArchREFSRCMasqueradeAudit[0].Anchor,
			KPINote: ArchREFSRCMasqueradeAudit[0].KPINote,
		},
		{
			Attr: "StreamBlocked",
			Masq: ArchREFSRCMasqueradeAudit[1].Masq,
			SB:   ArchREFSRCMasqueradeAudit[1].SB,
			Parity: ArchREFSRCMasqueradeAudit[1].Parity,
			Anchor: ArchREFSRCMasqueradeAudit[1].Anchor,
			KPINote: ArchREFSRCMasqueradeAudit[1].KPINote,
		},
		{
			Attr: "CONNECT upload",
			Masq: ArchREFSRCMasqueradeAudit[2].Masq,
			SB:   ArchREFSRCMasqueradeAudit[2].SB,
			Parity: ArchREFSRCMasqueradeAudit[2].Parity,
			Anchor: ArchREFSRCMasqueradeAudit[2].Anchor,
			KPINote: ArchREFSRCMasqueradeAudit[2].KPINote,
		},
		{
			Attr: "Download path",
			Masq: ArchREFSRCMasqueradeAudit[3].Masq,
			SB:   ArchREFSRCMasqueradeAudit[3].SB,
			Parity: ArchREFSRCMasqueradeAudit[3].Parity,
			Anchor: ArchREFSRCMasqueradeAudit[3].Anchor,
			KPINote: ArchREFSRCMasqueradeAudit[3].KPINote,
		},
		{
			Attr: "Server relay",
			Masq: ArchREFSRCMasqueradeAudit[5].Masq,
			SB:   ArchREFSRCMasqueradeAudit[5].SB,
			Parity: true,
			Anchor: ArchREFSRCMasqueradeAudit[5].Anchor,
			KPINote: ArchREFSRCMasqueradeAudit[5].KPINote,
		},
	}
}
