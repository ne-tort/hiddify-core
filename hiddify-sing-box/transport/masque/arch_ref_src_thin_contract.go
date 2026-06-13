package masque

// ArchREFSRCThinRelayRow documents masquethin vs stream/relay.go line parity (REF-SRC-THIN-2).
type ArchREFSRCThinRelayRow struct {
	ThinSymbol string
	StreamSymbol string
	Delegate   bool
	Note       string
}

// ArchREFSRCThinRelayAudit is frozen REF-SRC-THIN-1/2: internal/masquethin/relay.go → transport/masque/stream.
var ArchREFSRCThinRelayAudit = []ArchREFSRCThinRelayRow{
	{
		ThinSymbol: "RelayUploadFromStream()",
		StreamSymbol: "strm.RelayUploadFromStream()",
		Delegate: true,
		Note: "REF-SRC-THIN-1: MASQUE_THIN_RELAY_UPLOAD=str|stream default; reqbody via env",
	},
	{
		ThinSymbol: "RelayTCPTunnel(ctx, target, reqBody, w)",
		StreamSymbol: "strm.RelayTCPTunnel(ctx, target, reqBody, w)",
		Delegate: true,
		Note: "REF-SRC-THIN-2: zero fork — thin server uses same h2o-parity relay",
	},
}

// ArchREFSRCThinVsSBServerRow documents why thin server + sb client was fast (REF-SRC-THIN-3).
type ArchREFSRCThinVsSBServerRow struct {
	Factor   string
	Thin     string
	SBServer string
	KPIImpact string
}

// ArchREFSRCThinVsSBAudit explains bench ~554 thin vs ~15 sb (REF-SRC-THIN-3).
var ArchREFSRCThinVsSBAudit = []ArchREFSRCThinVsSBServerRow{
	{
		Factor: "Relay entry",
		Thin: "masquethin.RelayTCPTunnel → strm.RelayTCPTunnel",
		SBServer: "relay.TCPTunnel → strm.RelayTCPTunnel",
		KPIImpact: "same — not relay fork",
	},
	{
		Factor: "Listen bind",
		Thin: "127.0.0.1:4441 (no hairpin)",
		SBServer: "0.0.0.0:4439 hairpin artifact ~15; 127.0.0.1 ~374",
		KPIImpact: "bench attribution; remote s-ui :4438 still ~15",
	},
	{
		Factor: "Endpoint wrap",
		Thin: "masque-thin-server / authority-serve — no box.New",
		SBServer: "s-ui LaunchMasqueStack + ServerEndpoint delegate",
		KPIImpact: "wrap not relay; prod ceiling = client wire FC",
	},
	{
		Factor: "Thin listen in s-ui",
		Thin: "LaunchAuthorityThinHTTPServer (127.0.0.1 bind)",
		SBServer: "MASQUE_SERVER_THIN or MASQUE_SERVER_TEMPLATE_THIN_LISTEN → same thin listen + template mux",
		KPIImpact: "REF-SRC-THIN-4: no authority client transport required",
	},
}
