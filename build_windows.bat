@echo off
set GOOS=windows
set GOARCH=amd64
set CC=x86_64-w64-mingw32-gcc
set CGO_ENABLED=1
go run ./cli tunnel exit
del bin\hiddify-core.dll bin\HiddifyCli.exe
set CGO_LDFLAGS=
REM Keep in sync with Makefile TAGS / build_tags.txt
set TAGS=with_gvisor,with_quic,with_wireguard,with_utls,with_grpc,with_awg,tfogo_checklinkname0,with_naive_outbound,with_conntrack,with_xhttp,with_mieru,with_derp,with_shadowquic,with_sudoku,with_trusttunnel,with_carrier_client,with_carrier_vk,with_carrier_jitsi,with_carrier_telemost,with_carrier_wbstream,with_balancer,with_purego,badlinkname
go build -trimpath -tags %TAGS% -ldflags="-w -s" -buildmode=c-shared -o bin/hiddify-core.dll ./custom
go get github.com/akavel/rsrc
go install github.com/akavel/rsrc

rsrc  -ico .\assets\hiddify-cli.ico -o cli\bydll\cli.syso

copy bin\hiddify-core.dll .
set CGO_LDFLAGS="hiddify-core.dll"
go build  -o bin/HiddifyCli.exe ./cli/bydll/
del hiddify-core.dll
