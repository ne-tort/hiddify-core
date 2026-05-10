# Run MASQUE protocol/transport tests on the host GOOS.
# Fixes: "%%1 is not a valid Win32 application" when GOOS/GOARCH are stuck from linux cross-builds.
$ErrorActionPreference = "Stop"
$coreRoot = Split-Path $PSScriptRoot -Parent
$singbox = Join-Path $coreRoot "hiddify-sing-box"
if (-not (Test-Path $singbox)) {
    Write-Error "Expected hiddify-sing-box at: $singbox"
    exit 1
}
Push-Location $singbox
try {
    Remove-Item Env:GOOS -ErrorAction SilentlyContinue
    Remove-Item Env:GOARCH -ErrorAction SilentlyContinue
    go test ./protocol/masque/... ./transport/masque/... -count=1 @args
    exit $LASTEXITCODE
}
finally {
    Pop-Location
}
