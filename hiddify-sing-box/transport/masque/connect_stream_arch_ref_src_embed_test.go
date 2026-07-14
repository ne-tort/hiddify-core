//go:build masque_arch_ledger

package masque

import _ "embed"

//go:embed h3/tunnel.go
var archH3TunnelSource string

//go:embed h3/tunnel_conn.go
var archH3TunnelConnSource string

//go:embed h3/tunnel_from_response.go
var archH3TunnelFromResponseSource string

//go:embed stream/relay/relay.go
var archRelayEntrySource string

//go:embed stream/relay/relay_h2.go
var archRelayH2Source string

//go:embed stream/relay/relay_h3.go
var archRelayH3Source string

//go:embed stream/relay/relay_copy.go
var archRelayCopySource string

func archH3InvisvAuditSource() string {
	return archH3TunnelSource + archH3TunnelConnSource + archH3TunnelFromResponseSource
}

func archRelayGoAuditSource() string {
	return archRelayEntrySource + archRelayH2Source + archRelayH3Source + archRelayCopySource
}
