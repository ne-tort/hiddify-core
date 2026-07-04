package masque

// ArchREFSRCH2InvisvRow documents one Invisv H2 CONNECT-stream attribute vs sing-box (REF-SRC-INVISV-H2).
type ArchREFSRCH2InvisvRow struct {
	ID     string
	Attr   string
	Invisv string
	Ours   string
	Status string // MATCH | ADAPT | OPEN
}

// ArchREFSRCH2InvisvAudit is the frozen Invisv http2/client.go CreateTCPStream vs prod CONNECT-stream H2.
var ArchREFSRCH2InvisvAudit = []ArchREFSRCH2InvisvRow{
	{ID: "REF-H2-INV-1", Attr: "Upload pipe", Invisv: "io.Pipe (block-per-chunk)", Ours: "128 KiB bounded (H8 prod)", Status: "ADAPT"},
	{ID: "REF-H2-INV-2", Attr: "CONNECT form", Invisv: "classic CONNECT", Ours: "Extended CONNECT :protocol", Status: "ADAPT"},
	{ID: "REF-H2-INV-3", Attr: "Download read", Invisv: "resp.Body direct", Ours: "bufio 256 KiB + deadline wrapper", Status: "OPEN"},
	{ID: "REF-H2-INV-4", Attr: "x/net upload flush", Invisv: "stock per-DATA", Ours: "bulk 256 KiB + 3 ms deadline", Status: "ADAPT"},
	{ID: "REF-H2-INV-5", Attr: "Download WINDOW", Invisv: "stock ~4 KiB batch", Ours: "eager per-read + poke", Status: "ADAPT"},
	{ID: "REF-H2-INV-6", Attr: "Bidi poke/bootstrap", Invisv: "none", Ours: "4 KiB bootstrap + per-chunk poke", Status: "ADAPT"},
	{ID: "REF-H2-INV-7", Attr: "Duplex pump", Invisv: "stock RoundTrip body", Ours: "writeRequestMasqueDuplex sustained", Status: "ADAPT"},
}

// ArchREFSRCH2InvisvVerdict summarizes post-H8 ref gap (2026-07-04 PM Docker @0ms).
const ArchREFSRCH2InvisvVerdict = "H8 shallow pipe closed main gap; H14 Invisv composite FALSIFIED; H15 stock duplex same upload ~4.3 Gbit/s — writeRequestMasqueDuplex not ceiling; H2 ~4.3 vs H3 ~7 Gbit/s is H2/TLS stack class"

// ArchREFSRCH2InvisvSourceNeedles are frozen substrings in Invisv http2/client.go (upstream audit).
var ArchREFSRCH2InvisvSourceNeedles = []string{
	"pr, pw := io.Pipe()",
	`http.NewRequest("CONNECT", dst, pr)`,
	"IoOut: resp.Body",
}
