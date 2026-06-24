package h2

// Leg-profile env overrides (W-UDP-2t). Default hot-path shape is per stream role in leg_profile.go;
// these knobs override profile defaults for Docker burst / bisect only.
//
//   MASQUE_H2_DOWNLINK_IMMEDIATE_FLUSH=1 — force per-chunk server S2C flush (fountain bisect; NEVER default)
//   MASQUE_H2_CONNECT_UDP_UPLOAD_STREAMS=N — intra-flow upload leg fan-out (default 1; N>1 on shared TCP regresses single-flow @512 B)
//   MASQUE_H2_CONNECT_UDP_ASYMMETRIC_DUPLEX=1 — asymmetric legs per UDPFlow (default on)
//
// MasqueDocumentedEnvVars in package masque lists the os.Getenv names for hygiene gates.
