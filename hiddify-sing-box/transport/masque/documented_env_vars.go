package masque

// MasqueDocumentedEnvVars is the canonical registry of MASQUE knobs read in
// production Go (non-test) under transport/masque and protocol/masque. Keep sorted.
// Hygiene gate: TestMasqueDocumentedEnvVarsExist (H-S22).
//
// CONNECT-IP dataplane: zero-env (W-ZERO-ENV-PROD-PLAN) — no HIDDIFY_* / MASQUE_CONNECT_IP_* in prod hot path.
var MasqueDocumentedEnvVars = []string{
	"MASQUE_EXPERIMENTAL_QUIC",
}
