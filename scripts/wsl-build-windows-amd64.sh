#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
export PATH="$PATH:$(go env GOPATH)/bin"
if ! command -v rsrc >/dev/null 2>&1; then
  go install github.com/akavel/rsrc@latest
fi
# Go 1.26.x + MinGW can fail link with undefined internal/poll.execIO; pin 1.25 for c-shared if needed.
export GOTOOLCHAIN=${GOTOOLCHAIN:-go1.25.6}
export MINGW_CC=${MINGW_CC:-x86_64-w64-mingw32-gcc-15-posix}
make windows-amd64
echo "OK: bin contents:"
ls -la bin/
