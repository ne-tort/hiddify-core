#!/usr/bin/env bash
# Same packages as go-test-masque.ps1, for WSL/Linux (avoids Windows shell env leakage).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT/hiddify-sing-box"
unset GOOS GOARCH 2>/dev/null || true
exec go test ./protocol/masque/... ./transport/masque/... -count=1 "$@"
