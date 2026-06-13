package masque

import strm "github.com/sagernet/sing-box/transport/masque/stream"

// ArchREFSRCServerCallChainRow documents one hop in template CONNECT-stream server path (REF-SRC-SB-1).
type ArchREFSRCServerCallChainRow struct {
	Layer    string
	Symbol   string
	Next     string
	Parity   bool
	Note     string
}

// ArchREFSRCServerCallChain is the frozen REF-SRC-SB-1 call chain: mux → handler → relay → target.
var ArchREFSRCServerCallChain = []ArchREFSRCServerCallChainRow{
	{
		Layer: "L5 mux", Symbol: "server.BuildMuxHandler tcpPath",
		Next: "server.HandleTCPConnectRequest", Parity: true,
		Note: "template tcp_relay=template; authority uses HandleTCPConnectAuthority",
	},
	{
		Layer: "L5 handler", Symbol: "server.HandleTCPConnectRequest",
		Next: "relay.TCPForward", Parity: true,
		Note: "EnableFullDuplex → WriteHeader 200 → Flush → relay",
	},
	{
		Layer: "L5 relay entry", Symbol: "relay.TCPForward",
		Next: "relay.TCPTunnel → strm.RelayTCPTunnel", Parity: true,
		Note: "MASQUE_RELAY_TCP_LEGACY=1 → TCPBidirectional (not default)",
	},
	{
		Layer: "L5 tunnel", Symbol: "strm.RelayTCPTunnel",
		Next: "relayTCPTunnelBidiStream (H3 hijack) | EnableFullDuplex fallback (H2)",
		Parity: true,
		Note: "MASQUE_RELAY_TCP_STREAM_HIJACK=0 skips hijack",
	},
	{
		Layer: "endpoint wrap", Symbol: "endpoint_server.handleTCPConnectRequest",
		Next: "server.HandleTCPConnectRequest (delegate only)", Parity: true,
		Note: "REF-SRC-SB-2: no alternate relay in ServerEndpoint adapter",
	},
}

// ArchREFSRCServerUploadRow documents upload path parity vs h2o/thin (REF-SRC-SB-4).
type ArchREFSRCServerUploadRow struct {
	Path     string
	Chunk    int
	H2OParity bool
	Anchor   string
	Note     string
}

// ArchREFSRCServerUploadAudit is frozen REF-SRC-SB-4: default tunnel upload vs legacy relayUploadCopy.
var ArchREFSRCServerUploadAudit = []ArchREFSRCServerUploadRow{
	{
		Path: "H3 hijack default", Chunk: strm.RelayTunnelBufLen, H2OParity: true,
		Anchor: "stream/relay.go:relayTunnelCopyBufferBidiUpload + RelayUploadFromStream",
		Note: "per-chunk MasqueWakeBidiDuplex on upload read (REF5-SRV-3); MASQUE_THIN_RELAY_UPLOAD=str default",
	},
	{
		Path: "H3 reqbody override", Chunk: strm.RelayTunnelBufLen, H2OParity: true,
		Anchor: "stream/relay.go:relayTunnelUploadSource",
		Note: "MASQUE_RELAY_TCP_UPLOAD_BODY=1 reads req.Body not stream",
	},
	{
		Path: "Legacy flush relay", Chunk: 512 * 1024, H2OParity: false,
		Anchor: "protocol/masque/relay/legacy_flush.go:uploadCopy",
		Note: "MASQUE_RELAY_TCP_LEGACY=1 only; 512 KiB — not prod default",
	},
}

// ArchREFSRCServerDownloadRow documents download path parity (REF-SRC-SB-5).
type ArchREFSRCServerDownloadRow struct {
	Path      string
	Flush     string
	H2OParity bool
	Anchor    string
	Note      string
}

// ArchREFSRCServerDownloadAudit is frozen REF-SRC-SB-5: H3 io.CopyBuffer + H2 prime/flush batch.
var ArchREFSRCServerDownloadAudit = []ArchREFSRCServerDownloadRow{
	{
		Path: "H3 hijack download", Flush: "none (QUIC stream framing)",
		H2OParity: true, Anchor: "stream/relay.go:relayTCPTunnelBidiStream download goroutine",
		Note: "relayTunnelSetBidiDownloadActive + relayTunnelCopyBufferBidiDownload per-chunk MasqueWakeBidiDuplex (REF5-SRV-1)",
	},
	{
		Path: "H2 EnableFullDuplex", Flush: "RelayTunnelFlushBytes=65536",
		H2OParity: true, Anchor: "stream/relay.go:relayTunnelDownloadRelay",
		Note: "prime iperf banner + io.CopyBuffer bulk; downloadPathAdapter is client H2 only",
	},
}

// ArchREFSRCServerThinRow documents ServerThin / authority parity (REF-SRC-SB-3).
type ArchREFSRCServerThinRow struct {
	Flag     string
	Relay    string
	Parity   bool
	Note     string
}

// ArchREFSRCServerThinAudit is frozen REF-SRC-SB-2/3: box wrap vs thin authority listen.
var ArchREFSRCServerThinAudit = []ArchREFSRCServerThinRow{
	{
		Flag: "default s-ui / box", Relay: "LaunchMasqueStack + same HandleTCPConnectRequest",
		Parity: true, Note: "H3 datagrams on; H2 collateral; relay.TCPTunnel unchanged",
	},
	{
		Flag: "MASQUE_SERVER_THIN / CONNECT_STREAM_ONLY", Relay: "template mux only → HandleTCPConnectRequest",
		Parity: true, Note: "UDP/IP 404; same relay entry as full endpoint",
	},
	{
		Flag: "MASQUE_SERVER_TEMPLATE_THIN_LISTEN / ServerThin", Relay: "LaunchAuthorityThinHTTPServer + template mux (no authority client)",
		Parity: true, Note: "REF-SRC-THIN-4: thin QUIC listen inside s-ui without authority transport",
	},
	{
		Flag: "authorityMinimal + std TLS", Relay: "LaunchAuthorityThinHTTPServer → authority handler",
		Parity: true, Note: "MasqueAuthorityHTTPServerQUICConfig; masquethin/relay.go delegates to strm",
	},
}

// ArchREFSRCServerRelayKPI documents REF-SRC-SB-6 synth verdict after h2o-parity patch.
type ArchREFSRCServerRelayKPI struct {
	Leg           string
	ExpectMbps    string
	PassCondition string
	Verdict       string
}

// ArchREFSRCServerRelayKPIAudit is frozen REF-SRC-SB-6: instant relay >21; windowed sb-peer = wire FC.
var ArchREFSRCServerRelayKPIAudit = ArchREFSRCServerRelayKPI{
	Leg:           "TestArchServerH2OParityRelayL3 / S16 windowed band",
	ExpectMbps:    "instant >>21; windowed 4–28 (sb-peer FC model)",
	PassCondition: "instant > connectStreamVPSKPITargetDownMbps; windowed band not KPI pass alone",
	Verdict:       "h2o-parity relay OK; K-REF-B ceiling needs client S2C FC (REF2-2) not more server flush",
}
