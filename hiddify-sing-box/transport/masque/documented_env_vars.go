package masque

// MasqueDocumentedEnvVars is the canonical registry of MASQUE knobs read in
// production Go (non-test) under transport/masque and protocol/masque. Keep sorted.
// Hygiene gate: TestMasqueDocumentedEnvVarsExist (H-S22).
//
// Prod CONNECT-stream / H3 / CONNECT-UDP: zero-env. Rejected JSON quic_experimental
// (baked FinalizeConnectStreamQUICConfig only).
var MasqueDocumentedEnvVars = []string{}
