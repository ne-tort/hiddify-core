@echo off
set GOOS=windows
set GOARCH=amd64
set CC=x86_64-w64-mingw32-gcc
set CGO_ENABLED=1
go run ./cli tunnel exit
del bin\hiddify-core.dll bin\HiddifyCli.exe
set CGO_LDFLAGS=
for /f "delims=" %%T in ('go run ./cmd/print_core_build_tags -windows') do set "HIDDIFY_TAGS=%%T"
go build -trimpath -tags "%HIDDIFY_TAGS%" -ldflags="-w -s -checklinkname=0" -buildmode=c-shared -o bin/hiddify-core.dll ./custom
go get github.com/akavel/rsrc
go install github.com/akavel/rsrc

rsrc  -ico .\assets\hiddify-cli.ico -o cli\bydll\cli.syso

copy bin\hiddify-core.dll .
set CGO_LDFLAGS="hiddify-core.dll"
go build  -o bin/HiddifyCli.exe ./cli/bydll/
del hiddify-core.dll
