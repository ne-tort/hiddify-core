package masque

// ArchInvisvThinRow documents one Invisv H3 CreateTCPStream attribute vs thin CONNECT-stream dial (REF3-1).
type ArchInvisvThinRow struct {
	Attr     string
	Invisv   string
	Thin     string
	Parity   bool
	Anchor   string
	KPINote  string
}

// ArchInvisvThinAudit is the frozen REF3-1 differential: Invisv http3/client.go vs MASQUE_CONNECT_STREAM_THIN.
var ArchInvisvThinAudit = []ArchInvisvThinRow{
	{
		Attr: "CONNECT URL", Invisv: "https://host:port/", Thin: "template_tcp expanded URL (authority: https://target:port/)",
		Parity: true, Anchor: "h3/ConnectRequest + authority ExpandAuthorityConnectURL",
		KPINote: "shape differs by transport; both use nil Body bidi stream",
	},
	{
		Attr: "Request body", Invisv: "nil (not http.NoBody)", Thin: "nil Body, no io.Pipe",
		Parity: true, Anchor: "h3/ConnectRequest usePipe=false",
		KPINote: "MASQUE_CONNECT_STREAM_THIN forces PIPE_UPLOAD=0",
	},
	{
		Attr: "After 200", Invisv: "HTTPStreamer → quic.Stream", Thin: "HTTPStreamer → *http3.Stream",
		Parity: true, Anchor: "h3/tunnel_from_response.go:tunnelConnFromConnectResponse",
		KPINote: "requires quic-go-patched hijackableBody",
	},
	{
		Attr: "Download WriteTo", Invisv: "io.Copy on stream", Thin: "io.CopyBuffer 64 KiB on h3 (duplex_coord off)",
		Parity: true, Anchor: "h3/tunnel_conn.go:WriteTo",
		KPINote: "MASQUE_CONNECT_STREAM_THIN disables duplex_coord interleave",
	},
	{
		Attr: "feeder / ring", Invisv: "none", Thin: "none (no streamConn feeder)",
		Parity: true, Anchor: "stream/TunnelConn wraps h3.TunnelConn only",
		KPINote: "thin path skips P1 pipe upload stack",
	},
}
