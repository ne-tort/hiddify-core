package masque

// ArchMasqueradeThinRow documents one masquerade client.rs attribute vs sb CONNECT-stream (REF3-2).
type ArchMasqueradeThinRow struct {
	Attr    string
	Masq    string
	SB      string
	Parity  bool
	Anchor  string
	KPINote string
}

// ArchMasqueradeStreamBlockedAudit is the frozen REF3-2 subset of ArchREFSRCMasqueradeAudit (REF-SRC-MASQ-1/2).
var ArchMasqueradeStreamBlockedAudit = archMasqueradeREF3Rows()
