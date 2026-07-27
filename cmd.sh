#!/usr/bin/env bash
# Keep in sync with Makefile TAGS / build_tags.txt (lx: mieru, derp, carrier, balancer).
set -euo pipefail
TAGS=with_gvisor,with_quic,with_wireguard,with_utls,with_grpc,with_awg,tfogo_checklinkname0,with_naive_outbound,with_conntrack,with_xhttp,with_mieru,with_derp,with_shadowquic,with_sudoku,with_trusttunnel,with_carrier_client,with_carrier_vk,with_carrier_jitsi,with_carrier_telemost,with_carrier_wbstream,with_balancer,with_purego,badlinkname
go run --tags "$TAGS" ./cmd/main "$@"
