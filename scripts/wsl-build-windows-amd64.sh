#!/usr/bin/env bash
# Cross-compile Windows amd64 libcore from WSL/Linux (MinGW).
# Called from repo root: bash hiddify-core/scripts/wsl-build-windows-amd64.sh
# Equivalent: make build-windows-libs
set -euo pipefail

CORE_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
make -C "$CORE_ROOT" windows-amd64
echo "OK: $CORE_ROOT/bin/hiddify-core.dll HiddifyCli.exe libcronet.dll"
