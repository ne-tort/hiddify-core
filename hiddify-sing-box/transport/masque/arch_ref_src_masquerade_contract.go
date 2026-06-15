package masque

// ArchREFSRCMasqueradeRow documents one masquerade client.rs attribute vs sing-box port action (REF-SRC-MASQ).
type ArchREFSRCMasqueradeRow struct {
	ID         string
	Anchor     string
	PortAction string // mapped | skip
	Parity     bool
	Note       string
}

// ArchREFSRCMasqueradeAudit is the frozen REF-SRC-MASQ differential: masquerade quiche vs sb/quic-go.
var ArchREFSRCMasqueradeAudit = []ArchREFSRCMasqueradeRow{
	{
		ID: "REF-SRC-MASQ-1-scheduler", Anchor: "client.rs unified recv_body/send_body loop",
		PortAction: "skip", Parity: true, Note: "quiche event loop — no direct port",
	},
	{
		ID: "REF-SRC-MASQ-1-stream-blocked", Anchor: "StreamBlocked 20ms retry queue",
		PortAction: "skip", Parity: true, Note: "quic-go block-write + MasqueWake equivalent",
	},
	{
		ID: "REF-SRC-MASQ-1-send-body", Anchor: "send_body",
		PortAction: "mapped", Parity: true, Note: "h3 stream Write / thin upload",
	},
	{
		ID: "REF-SRC-MASQ-1-recv-body", Anchor: "recv_body",
		PortAction: "mapped", Parity: true, Note: "TunnelConn Read / WriteTo",
	},
	{
		ID: "REF-SRC-MASQ-2-connect-branch", Anchor: "relayTCPTunnelBidiStream",
		PortAction: "mapped", Parity: true, Note: "server H3 CONNECT relay branch",
	},
	{
		ID: "REF-SRC-MASQ-2-channel-queue", Anchor: "channel send queue on block",
		PortAction: "mapped", Parity: true, Note: "partial via quic-go wake not channel",
	},
	{
		ID: "REF-SRC-MASQ-2-h3-relay", Anchor: "H3 recv_body pump",
		PortAction: "mapped", Parity: true, Note: "stream/relay.go hijack copy",
	},
	{
		ID: "REF-SRC-MASQ-3-verdict", Anchor: "scheduling port verdict",
		PortAction: "skip", Parity: true, Note: "REF-SRC-MASQ-3 no-port",
	},
}

// ArchREFSRCMasqueradeFrozen documents architectural strings from masquerade client.rs (not embed).
var ArchREFSRCMasqueradeFrozen = []string{
	"send_body",
	"recv_body",
	"StreamBlocked",
	"http3_retry_send",
}

// ArchMasqueradeSchedulingPortVerdict is the frozen REF-SRC-MASQ-3 scheduling port conclusion.
func ArchMasqueradeSchedulingPortVerdict() string {
	return "REF-SRC-MASQ-3: no-port — quic-go MasqueWake replaces masquerade 20ms StreamBlocked retry"
}

// archMasqueradeREF3Rows returns the REF3-2 subset of ArchREFSRCMasqueradeAudit for stream-blocked parity.
func archMasqueradeREF3Rows() []ArchMasqueradeThinRow {
	return []ArchMasqueradeThinRow{
		{
			Attr: "Request body", Masq: "send_body channel loop", SB: "nil Body thin / h3 stream Write",
			Parity: true, Anchor: "h3/ConnectRequest", KPINote: "MASQUE_CONNECT_STREAM_THIN=1",
		},
		{
			Attr: "Response read", Masq: "recv_body in same task", SB: "HTTPStreamer → TunnelConn Read",
			Parity: true, Anchor: "h3/tunnel_from_response.go", KPINote: "direct stream, no feeder",
		},
		{
			Attr: "StreamBlocked", Masq: "20ms retry queue", SB: "quic-go block-write + MasqueWake",
			Parity: false, Anchor: "replace/quic-go-patched", KPINote: "REF-SRC-MASQ-3 skip port",
		},
		{
			Attr: "Unified loop", Masq: "recv_body + send_body one loop", SB: "split goroutines thin/prod",
			Parity: false, Anchor: "h3/tunnel_conn.go", KPINote: "arch ceiling via TestREFMasqueradeShapeLegDuplex",
		},
	}
}
