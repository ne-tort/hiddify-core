# MASQUE CONNECT-IP Production Closure

## Current State
- `tcp_transport=connect_ip` is **not** allowed in TUN-only client profiles; production TCP-over-CONNECT-IP means `transport_mode=connect_ip` + netstack packet-plane.
- Default `TCPNetstackFactory` is now lifecycle-safe and provides a working TCP path.
- `MASQUE_EXPERIMENTAL_TCP_CONNECT_IP` is no longer required for standard CONNECT-IP validation.

## Production Hardening Gates
1. Keep lifecycle-safe teardown for stack/session reuse across retries and close races.
2. Maintain integration coverage:
   - success path dial/read/write/close,
   - retry path on transient transport failures,
   - close-race safety and idempotent shutdown,
   - fallback-policy invariants (`strict_masque` fail-closed).
3. Keep dedicated e2e stand scenarios for CONNECT-IP TCP dataplane in CI/nightly:
   - smoke/negative gate via unified Python runner `python experiments/router/stand/l3router/masque_stand_runner.py --scenario tcp_ip` with deterministic JSON verdict,
   - anti-bypass negative control with MASQUE server down,
   - perf pair (max/shaped) through the same stand entrypoint or CI wrapper scripts when those scripts are present in the tree.

## Required Acceptance Signals
- deterministic JSON verdict artifacts for CONNECT-IP e2e runs.
- no typed `ErrTCPStackInit` in steady-state successful runs with default factory.
- no policy regressions vs `connect_stream` in strict profile.
