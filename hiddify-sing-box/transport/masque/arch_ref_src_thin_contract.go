package masque

// ArchREFSRCThinRelayRow documents removed masquethin path vs stream/relay.go parity (REF-SRC-THIN-2).
type ArchREFSRCThinRelayRow struct {
	ThinSymbol   string
	StreamSymbol string
	Delegate     bool
	Note         string
}

// ArchREFSRCThinRelayAudit is frozen REF-SRC-THIN-1/2: removed internal/masquethin/relay.go → transport/masque/stream.
var ArchREFSRCThinRelayAudit = []ArchREFSRCThinRelayRow{
	{
		ThinSymbol:   "removed: masquethin.RelayUploadFromStream()",
		StreamSymbol: "strm.RelayUploadFromStream()",
		Delegate:     true,
		Note:         "removed; prod relay uses strm.RelayUploadFromStream; MASQUE_THIN_RELAY_UPLOAD=str|stream default",
	},
	{
		ThinSymbol:   "removed: masquethin.RelayTCPTunnel(ctx, target, reqBody, w)",
		StreamSymbol: "strm.RelayTCPTunnel(ctx, target, reqBody, w)",
		Delegate:     true,
		Note:         "removed; prod server uses strm.RelayTCPTunnel directly (h2o-parity relay)",
	},
}

// ArchREFSRCThinVsSBServerRow documents why removed thin bench leg was fast vs sb server (REF-SRC-THIN-3).
type ArchREFSRCThinVsSBServerRow struct {
	Factor    string
	Thin      string
	SBServer  string
	KPIImpact string
}

// ArchREFSRCThinVsSBAudit explains bench ~554 removed thin vs ~15 sb (REF-SRC-THIN-3).
var ArchREFSRCThinVsSBAudit = []ArchREFSRCThinVsSBServerRow{
	{
		Factor:    "Relay entry",
		Thin:      "removed masquethin.RelayTCPTunnel → strm.RelayTCPTunnel",
		SBServer:  "relay.TCPTunnel → strm.RelayTCPTunnel",
		KPIImpact: "same — not relay fork",
	},
	{
		Factor:    "Listen bind",
		Thin:      "127.0.0.1:4441 (no hairpin)",
		SBServer:  "0.0.0.0:4439 hairpin artifact ~15; 127.0.0.1 ~374",
		KPIImpact: "bench attribution; remote s-ui :4438 still ~15",
	},
	{
		Factor:    "Endpoint wrap",
		Thin:      "removed masque-thin-server / authority-serve — no box.New",
		SBServer:  "s-ui LaunchMasqueStack + ServerEndpoint delegate",
		KPIImpact: "wrap not relay; prod ceiling = client wire FC",
	},
	{
		Factor:    "Thin listen in s-ui",
		Thin:      "removed LaunchAuthorityThinHTTPServer (127.0.0.1 bind)",
		SBServer:  "MASQUE_SERVER_CONNECT_STREAM_ONLY → template mux only",
		KPIImpact: "removed thin listen; prod connect_stream only",
	},
}
