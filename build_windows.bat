@echo off
setlocal
set GOOS=windows
set GOARCH=amd64
set CGO_ENABLED=1
REM Keep in sync with Makefile TAGS / build_tags.txt
set TAGS=with_gvisor,with_quic,with_wireguard,with_utls,with_grpc,with_awg,tfogo_checklinkname0,with_naive_outbound,with_conntrack,with_xhttp,with_mieru,with_derp,with_shadowquic,with_sudoku,with_trusttunnel,with_carrier_client,with_carrier_vk,with_carrier_jitsi,with_carrier_telemost,with_carrier_wbstream,with_balancer,with_purego,badlinkname

if not exist bin mkdir bin
if not exist bin\libcronet.dll (
  echo Extracting libcronet.dll...
  for /f %%V in (..\vendor\sing-box-lx\.github\CRONET_GO_VERSION) do set CRONET=%%V
  go run -v "github.com/sagernet/cronet-go/cmd/build-naive@%CRONET%" extract-lib --target windows/amd64 -o bin/
  if errorlevel 1 exit /b 1
)

echo Building hiddify-core.dll...
go build -trimpath -tags %TAGS%,with_purego -buildmode=c-shared -ldflags="-w -s -checklinkname=0" -o bin/hiddify-core.dll ./platform/desktop
if errorlevel 1 exit /b 1

echo Building HiddifyCli.exe...
copy /Y bin\hiddify-core.dll hiddify-core.dll >nul
set CGO_LDFLAGS=hiddify-core.dll
go build -trimpath -tags %TAGS%,with_purego -ldflags="-w -s -checklinkname=0" -o bin/HiddifyCli.exe ./cmd/bydll
set CGO_LDFLAGS=
del hiddify-core.dll 2>nul

if not exist bin\hiddify-core.dll (
  echo Error: bin\hiddify-core.dll not built
  exit /b 1
)
if not exist bin\HiddifyCli.exe (
  echo Error: bin\HiddifyCli.exe not built
  exit /b 1
)
echo OK: bin\hiddify-core.dll bin\HiddifyCli.exe bin\libcronet.dll
