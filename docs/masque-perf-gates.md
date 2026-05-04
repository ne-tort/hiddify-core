# MASQUE Data Plane Perf Gates

## Scope
This document defines practical performance and stability gates for `masque` and `warp_masque` data-plane behavior.

## Tracks

### 1) Smoke (PR blocking)
- Goal: catch fast regressions in contract and behavior.
- Commands:
  - `go test ./protocol/masque ./transport/masque ./common/masque ./include -tags with_masque`
  - `go test -race ./protocol/masque ./transport/masque -tags with_masque`
  - unified CONNECT-IP runner (canonical): `python experiments/router/stand/l3router/masque_stand_runner.py --scenario tcp_ip`
  - CI inline UDP smoke `10KB <= 5s` (`runtime/smoke_10kb_latest.json`)
  - CI inline TCP `connect_stream` smoke `10KB <= 5s` (`runtime/smoke_tcp_connect_stream_latest.json`)
- Expected runtime: under 10 minutes.

### 2) Stress (nightly, non-blocking for PR)
- Goal: measure throughput/loss/latency and failover behavior under load.
- Environment:
  - reuse stand patterns from `experiments/router/stand/l3router`.
  - run with Docker/WSL2 locally or Linux runner in CI.
- Metrics:
  - TCP and UDP throughput,
  - packet loss and jitter,
  - reconnect/failover recovery time.
- Deterministic artifact contract:
  - smoke prechecks (must be green before perf):
    - `runtime/smoke_10kb_latest.json`
    - `runtime/smoke_tcp_connect_stream_latest.json`
    - `runtime/smoke_tcp_connect_ip_latest.json`
  - `runtime/udp_perf_500mb_latest.json`
  - `runtime/udp_perf_500mb_shaped_50mbps_latest.json`
  - `runtime/tcp_stream_perf_500mb_latest.json`
  - `runtime/tcp_stream_perf_500mb_shaped_50mbps_latest.json`
  - `runtime/tcp_connect_ip_perf_500mb_latest.json`
  - `runtime/tcp_connect_ip_perf_500mb_shaped_50mbps_latest.json`
  - each artifact must contain `metrics`, `thresholds`, `error_class`, `result`.
  - each artifact must also contain stable top-level keys:
    - `test_id`, `mode`, `metrics`, `thresholds`, `error_class`, `result`.
  - `result` must be strictly boolean `true|false`, never omitted/nullable.
  - `mode` must match file semantics (`connect_udp` vs `connect_stream`).
  - metric sanity checks are mandatory (`elapsed_ms >= 0`, throughput/loss/bytes not negative).

### 3) Soak (weekly or manual release gate)
- Goal: long-run stability and drift detection.
- Duration: 4-24h.
- Metrics:
  - reconnect success ratio,
  - p95/p99 latency drift,
  - packet loss trend.

## Suggested minimum matrix
- `connect_udp` strict mode, normal load.
- `connect_udp` with hop failover.
- `connect_ip` client/server packet path.
- `connect_stream` tcp smoke (`strict_masque` + `masque_or_direct` policy checks).
- `connect_ip` tcp production contract gate (no experimental env requirement).
- `connect_udp` perf pair: max-rate + shaped-50mbps.
- `connect_stream` perf pair: max-rate + shaped-50mbps.
- `connect_ip` perf matrix: max-rate + shaped-50/75/100mbps.
- anti-bypass controls with MASQUE server down (both UDP and TCP smoke must fail).
- `warp_masque` bootstrap `reuse/create/recreate`.
- legacy `warp` no-break regression check.

## Reporting
- Store JSON summary per run with:
  - `test_id`,
  - `mode`,
  - `metrics`,
  - `thresholds`,
  - `error_class`,
  - `result`,
  - optional build commit metadata.
- Compare each stress/soak run against latest stable baseline.
- Initial threshold set (warning-oriented for nightly):
  - UDP/TCP max-rate: `min_throughput_mbps >= 5`.
  - UDP/TCP shaped 50mbps: `min_throughput_mbps >= 20`.
  - UDP loss: `max_loss_pct <= 5.00`.
  - all perf scripts must emit deterministic `result=true|false` from these thresholds.
- Threshold verification must be explicit in CI (contract check, not only script exit code):
  - `udp_perf_500mb_latest.json`: `thresholds.min_throughput_mbps == 5`, `thresholds.max_loss_pct == 5.00`.
  - `udp_perf_500mb_shaped_50mbps_latest.json`: `thresholds.min_throughput_mbps == 20`, `thresholds.max_loss_pct == 5.00`.
  - `tcp_stream_perf_500mb_latest.json`: `thresholds.min_throughput_mbps == 5`.
  - `tcp_stream_perf_500mb_shaped_50mbps_latest.json`: `thresholds.min_throughput_mbps == 20`.
  - `tcp_connect_ip_perf_500mb_latest.json`: `thresholds.min_throughput_mbps == 5`.
  - `tcp_connect_ip_perf_500mb_shaped_50mbps_latest.json`: `thresholds.min_throughput_mbps == 20`.
  - `tcp_connect_ip_perf_500mb_shaped_75mbps_latest.json`: `thresholds.min_throughput_mbps == 20`.
  - `tcp_connect_ip_perf_500mb_shaped_100mbps_latest.json`: `thresholds.min_throughput_mbps == 20`.
- Artifact completeness check:
  - CI fails nightly job if any required JSON is missing or malformed.
  - workflow-level non-blocking policy remains via `continue-on-error: true`.

## CI Integration
- PR/Push blocking gate:
  - workflow job `masque-gates` in `hiddify-core/.github/workflows/ci.yml`
  - CONNECT-IP checks run via stand runner flow (Python entrypoint); workflows may wrap it with local shell scripts when those scripts are present.
  - uploads `experiments/router/stand/l3router/runtime/smoke_10kb_latest.json`.
- Nightly non-blocking stress track:
  - workflow job `masque-nightly-perf` in `hiddify-core/.github/workflows/ci.yml`
  - executes smoke prechecks + perf pair (UDP/TCP max+shaped) + anti-bypass controls.
  - uploads runtime perf JSON artifacts for trend inspection.
  - validates artifacts by schema + threshold contract + sanity checks.
  - evaluates perf artifacts in CI without `|| true`; workflow remains non-blocking via `continue-on-error`.

