package relay

import _ "embed"

//go:embed relay.go
var relayEntryAuditSource string

//go:embed relay_h2.go
var relayH2AuditSource string

//go:embed relay_h3.go
var relayH3AuditSource string

//go:embed relay_copy.go
var relayCopyAuditSource string

func relayGoAuditBundle() string {
	return relayEntryAuditSource + relayH2AuditSource + relayH3AuditSource + relayCopyAuditSource
}
