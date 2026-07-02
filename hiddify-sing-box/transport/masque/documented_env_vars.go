package masque

// MasqueDocumentedEnvVars is the canonical registry of MASQUE/HIDDIFY_MASQUE knobs read in
// production Go (non-test) under transport/masque and protocol/masque. Keep sorted.
// Hygiene gate: TestMasqueDocumentedEnvVarsExist (H-S22).
//
// Lab-only CONNECT-IP (KEEP — not hardcoded): bootstrap strictness, OBS counters,
// netstack prefix wait. Prod dataplane uses safe defaults when unset.
var MasqueDocumentedEnvVars = []string{
	"MASQUE_CONNECT_IP_BOOTSTRAP_REQUIRE_PREFIX",
	"MASQUE_CONNECT_IP_OBS",
	"MASQUE_CONNECT_IP_ROUTE_SETUP_TIMEOUT",
	"MASQUE_CONNECT_IP_TCP_NETSTACK_PREFIX_WAIT_SEC",
	"MASQUE_CONNECT_UDP_DEBUG",
	"MASQUE_CONNECT_UDP_RELAY_STATS",
	"MASQUE_EXPERIMENTAL_QUIC",
}
