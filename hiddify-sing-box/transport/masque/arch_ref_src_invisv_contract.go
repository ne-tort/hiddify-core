package masque

// ArchREFSRCInvisvRow documents one Invisv H3 CONNECT-stream attribute vs sing-box thin dial (REF-SRC-INVISV).
type ArchREFSRCInvisvRow struct {
	ID   string
	Attr string
	Note string
}

// ArchREFSRCInvisvAudit is the frozen REF-SRC-INVISV differential: invisv-masque http3/client.go vs h3 thin path.
var ArchREFSRCInvisvAudit = []ArchREFSRCInvisvRow{
	{
		ID: "REF-SRC-INVISV-1", Attr: "CONNECT request",
		Note: "nil Body (not http.NoBody); no io.Pipe upload feeder",
	},
	{
		ID: "REF-SRC-INVISV-2", Attr: "After 200",
		Note: "HTTPStreamer → direct *http3.Stream Read/Write",
	},
	{
		ID: "REF-SRC-INVISV-3", Attr: "Download WriteTo",
		Note: "io.CopyBuffer 64 KiB on stream; no feeder ring",
	},
	{
		ID: "REF-SRC-INVISV-4", Attr: "Scheduler hooks",
		Note: "no masquerade channel loop; thin disables duplex_coord",
	},
}

// ArchREFSRCInvisvVerdict is the frozen REF-SRC-INVISV scope conclusion.
const ArchREFSRCInvisvVerdict = "thin dial matches Invisv nil-Body + HTTPStreamer; prod eager WINDOW unlocks KPI beyond stock quic-go"

// ArchREFSRCInvisvSourceNeedles are frozen substrings in h3 prod sources (embed audit).
var ArchREFSRCInvisvSourceNeedles = []string{
	"http.NewRequestWithContext(ctx, http.MethodConnect, url, nil)",
	"HTTPStreamer",
	"tunnelWriteToBufLen = 64 * 1024",
}
