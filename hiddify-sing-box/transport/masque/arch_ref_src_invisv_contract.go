package masque

// ArchREFSRCInvisvRow documents one Invisv masque reference attribute vs sing-box client (REF-SRC-INVISV).
type ArchREFSRCInvisvRow struct {
	ID       string
	Attr     string
	Invisv   string
	SB       string
	Parity   bool
	Anchor   string
	PatchRef string
}

// ArchREFSRCInvisvAudit is frozen REF-SRC-INVISV-1…4: repos/invisv-masque vs h3/tunnel_conn.go + quic patches.
var ArchREFSRCInvisvAudit = []ArchREFSRCInvisvRow{
	{
		ID: "REF-SRC-INVISV-1", Attr: "CreateTCPStream CONNECT",
		Invisv: "http.NewRequest(CONNECT, https://host:port/, nil); httpClient.Do",
		SB:     "prod template_tcp + connect_stream; h3/ConnectRequest usePipe=false default",
		Parity: true, Anchor: "repos/invisv-masque/http3/client.go:394-434; h3/tunnel.go",
	},
	{
		ID: "REF-SRC-INVISV-2", Attr: "Non-RFC client layers",
		Invisv: "none — direct quic.Stream after HTTPStreamer hijack",
		SB:     "feeder/pipe/dual_coord opt-in; prod h3_stream + eager WINDOW (ArchREFSRCSBClientNonRFC)",
		Parity: false, PatchRef: "MASQUE_CONNECT_STREAM_THIN=1 for Invisv-shaped dial; eager window default for KPI",
		Anchor: "arch_ref3_contract.go; arch_ref_src_sb_client_contract.go",
	},
	{
		ID: "REF-SRC-INVISV-3", Attr: "Symmetric relay (server ref)",
		Invisv: "example/relay-http-proxy: io.Copy both halves on masqueH2.Conn (H2 sample)",
		SB:     "stream/relay.go RelayTCPTunnel 64 KiB io.CopyBuffer goroutine split (h2o parity)",
		Parity: true, Anchor: "repos/invisv-masque/example/relay-http-proxy/main.go:192-195; stream/relay.go (H3 server ref = h2o)",
	},
	{
		ID: "REF-SRC-INVISV-4", Attr: "quic-go patches",
		Invisv: "replace → Invisv-Privacy/quic-go-upstream@7cefe04; stock WindowUpdateThreshold 0.05",
		SB:     "replace/quic-go-patched: masque_threshold.go threshold 0 when MASQUE_QUIC_DOWNLOAD_EAGER_WINDOW=1 (default); MasqueWake* hooks",
		Parity: false, PatchRef: "superset of Invisv fork — eager WINDOW + bidi wake not in upstream Invisv quic-go",
		Anchor: "repos/invisv-masque/go.mod replace; replace/quic-go-patched/internal/flowcontrol/masque_threshold.go",
	},
}

// ArchREFSRCInvisvVerdict is the frozen REF-SRC-INVISV wave conclusion.
const ArchREFSRCInvisvVerdict = "Invisv H3 client is thin HTTPStreamer path; KPI gap vs sb-peer is quic wake+WINDOW threshold (our patch), not missing server relay fork"
