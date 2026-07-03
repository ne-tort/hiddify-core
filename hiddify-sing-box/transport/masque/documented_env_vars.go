package masque

// MasqueDocumentedEnvVars is the canonical registry of MASQUE knobs read in
// production Go (non-test) under transport/masque and protocol/masque. Keep sorted.
// Hygiene gate: TestMasqueDocumentedEnvVarsExist (H-S22).
//
// CONNECT-IP / CONNECT-UDP dataplane: zero-env — no HIDDIFY_* / MASQUE_CONNECT_* in prod hot path.
// quic_experimental.enabled is JSON-only (no MASQUE_EXPERIMENTAL_QUIC).
var MasqueDocumentedEnvVars = []string{}
