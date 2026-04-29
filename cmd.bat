@echo off
for /f "delims=" %%T in ('go run ./cmd/print_core_build_tags -windows') do set "TAGS=%%T"
@REM tags: see cmd/internal/build_shared/core_build_tags.go
go run --tags "%TAGS%" ./cli %*