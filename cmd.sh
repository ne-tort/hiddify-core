#!/usr/bin/env bash
# TAGS from build_tags.txt (single source of truth)
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TAGS="$(grep -v '^[[:space:]]*#' "$ROOT/build_tags.txt" | grep -v '^[[:space:]]*$' | tr -d '\r' | head -n1)"
if [[ -z "${TAGS}" ]]; then
  echo "Error: could not read TAGS from build_tags.txt" >&2
  exit 1
fi
go run --tags "$TAGS" ./cmd/main "$@"
