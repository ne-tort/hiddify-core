#!/usr/bin/env bash
# Dev runner for hiddify-core CLI. Build tags = print_core_build_tags (with_masque by default).
# Prefer: go run ./cmd/print_core_build_tags  then go run --tags "..." ./cmd/main
set -euo pipefail
cd "$(dirname "$0")"
go mod tidy
TAGS="$(go run ./cmd/print_core_build_tags)"
go run --tags "$TAGS" ./cmd/main "$@"
