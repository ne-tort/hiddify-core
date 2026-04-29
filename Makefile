.ONESHELL:
ifeq ($(OS),Windows_NT)
  unexport GOOS GOARCH
endif
PRODUCT_NAME=hiddify-core
BASENAME=$(PRODUCT_NAME)
# Все собираемые бинарники и библиотеки — в $(BINDIR); не кладём их в корень модуля (кроме служебных *.syso рядом с пакетом, см. windows-amd64).
BINDIR=bin
LIBNAME=$(PRODUCT_NAME)
CLINAME=HiddifyCli

BRANCH=$(shell git branch --show-current)
VERSION=$(shell git describe --tags || echo "unknown version")
# windows-amd64 и прочие цели ниже — POSIX shell + bash-рецепты (.ONESHELL).
# Запускайте из WSL/Linux, либо из Git Bash / MSYS2 на Windows (MinGW в PATH), не из cmd.exe.
CRONET_GO_VERSION := $(shell cat hiddify-sing-box/.github/CRONET_GO_VERSION)
# Единый список с s-ui / build_libbox: cmd/internal/build_shared/core_build_tags.go
HIDDIFY_CORE_ROOT := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))
TAGS := $(shell cd "$(HIDDIFY_CORE_ROOT)" && go run ./cmd/print_core_build_tags)
IOS_ADD_TAGS=with_dhcp,with_low_memory,with_purego
MACOS_ADD_TAGS=with_dhcp
WINDOWS_ADD_TAGS=with_purego
# Override on WSL if default mingw fails Go c-shared link (e.g. MINGW_CC=x86_64-w64-mingw32-gcc-15-posix).
MINGW_CC ?= x86_64-w64-mingw32-gcc
# Системный Go 1.26+ при сборке c-shared для windows/amd64 из Linux/macOS даёт линковочную ошибку
# undefined reference to internal/poll.execIO. Совпадаем с версией в go.mod (см. go.dev/doc/toolchain).
WINDOWS_GOTOOLCHAIN ?= go1.25.6
LDFLAGS=-w -s -checklinkname=0 -buildid= $${CODE_VERSION}
GOBUILDLIB=CGO_ENABLED=1 go build -trimpath -ldflags="$(LDFLAGS)" -buildmode=c-shared
GOBUILDSRV=CGO_ENABLED=1 go build -ldflags="$(LDFLAGS)" -trimpath -tags $(TAGS)
# Windows: тот же набор, что и у DLL (TAGS + purego), иначе bydll и libcronet расходятся.
GOBUILDSRV_WIN=CGO_ENABLED=1 go build -ldflags="$(LDFLAGS)" -trimpath -tags $(TAGS),$(WINDOWS_ADD_TAGS)

CRONET_DIR=./cronet
.PHONY: protos
protos:
	go install github.com/pseudomuto/protoc-gen-doc/cmd/protoc-gen-doc@latest
	# protoc --go_out=./ --go-grpc_out=./ --proto_path=hiddifyrpc hiddifyrpc/*.proto
	# for f in $(shell find v2 -name "*.proto"); do \
	# 	protoc --go_opt=paths=source_relative --go-grpc_opt=paths=source_relative --go_out=./ --go-grpc_out=./  $$f; \
	# done
	# for f in $(shell find extension -name "*.proto"); do \
	# 	protoc --go_opt=paths=source_relative --go-grpc_opt=paths=source_relative --go_out=./ --go-grpc_out=./  $$f; \
	# done
	protoc --go_opt=paths=source_relative --go-grpc_opt=paths=source_relative --go_out=./ --go-grpc_out=./  $(shell find v2 -name "*.proto") $(shell find extension -name "*.proto")
	protoc --doc_out=./docs  --doc_opt=markdown,hiddifyrpc.md $(shell find v2 -name "*.proto") $(shell find extension -name "*.proto")
	# protoc --js_out=import_style=commonjs,binary:./extension/html/rpc/ --grpc-web_out=import_style=commonjs,mode=grpcwebtext:./extension/html/rpc/ $(shell find v2 -name "*.proto") $(shell find extension -name "*.proto")
	# npx browserify extension/html/rpc/extension.js >extension/html/rpc.js


lib_install: prepare
	go install -v github.com/sagernet/gomobile/cmd/gomobile@v0.1.11
	go install -v github.com/sagernet/gomobile/cmd/gobind@v0.1.11
	npm install

headers:
	go build -buildmode=c-archive -o $(BINDIR)/ ./platform/desktop2

android: lib_install
	CGO_LDFLAGS="-O2 -g -s -w -Wl,-z,max-page-size=16384" gomobile bind -v -androidapi=21 -javapkg=com.hiddify.core -libname=hiddify-core -tags=$(TAGS) -trimpath -ldflags="$(LDFLAGS)" -target=android -gcflags "all=-N -l" -o $(BINDIR)/$(LIBNAME).aar github.com/sagernet/sing-box/experimental/libbox ./platform/mobile

ios-full: lib_install
	gomobile bind -v  -target ios,iossimulator,tvos,tvossimulator,macos -libname=hiddify-core -tags=$(TAGS),$(IOS_ADD_TAGS) -trimpath -ldflags="$(LDFLAGS)" -o $(BINDIR)/$(PRODUCT_NAME).xcframework github.com/sagernet/sing-box/experimental/libbox ./platform/mobile 
	mv $(BINDIR)/$(PRODUCT_NAME).xcframework $(BINDIR)/$(LIBNAME).xcframework 
	cp HiddifyCore.podspec $(BINDIR)/$(LIBNAME).xcframework/

ios: lib_install
	gomobile bind -v  -target ios -libname=hiddify-core -tags=$(TAGS),$(IOS_ADD_TAGS) -trimpath -ldflags="$(LDFLAGS)" -o $(BINDIR)/HiddifyCore.xcframework github.com/sagernet/sing-box/experimental/libbox ./platform/mobile
	cp Info.plist $(BINDIR)/HiddifyCore.xcframework/


webui:
	curl -L -o webui.zip  https://github.com/hiddify/Yacd-meta/archive/gh-pages.zip 
	unzip -d ./ -q webui.zip
	rm webui.zip
	rm -rf bin/webui
	mv Yacd-meta-gh-pages bin/webui

.PHONY: build
windows-amd64: prepare
	set -e
	export GOTOOLCHAIN="$(WINDOWS_GOTOOLCHAIN)"
	# Остаток прерванной сборки: DLL в корне совпадает по имени с аргументом линкера и ломает link (in=out).
	rm -f $(LIBNAME).dll
	rm -rf $(BINDIR)/*
	CRONET_LIB_DIR=$$(go list -m -f '{{.Dir}}' github.com/sagernet/cronet-go/lib/windows_amd64) && \
	cp "$$CRONET_LIB_DIR/libcronet.dll" $(BINDIR)/libcronet.dll
	env GOOS=windows GOARCH=amd64 CC=$(MINGW_CC)  $(GOBUILDLIB) -tags $(TAGS),$(WINDOWS_ADD_TAGS)   -o $(BINDIR)/$(LIBNAME).dll ./platform/desktop
	echo "core built, now building cli" 
	ls -R $(BINDIR)/
	RSRC_BIN=$$(go env GOPATH)/bin/rsrc && \
	test -x "$$RSRC_BIN"
	# .syso обязан лежать в каталоге пакета — его подхватывает go build (не переносим в bin/).
	$$RSRC_BIN -ico ./assets/hiddify-cli.ico -o ./cmd/bydll/cli.syso
	env GOOS=windows GOARCH=amd64 CC=$(MINGW_CC) CGO_LDFLAGS="$(BINDIR)/$(LIBNAME).dll" $(GOBUILDSRV_WIN) -o $(BINDIR)/$(CLINAME).exe ./cmd/bydll
	rm -f $(LIBNAME).dll
	if [ ! -f $(BINDIR)/$(LIBNAME).dll -o ! -f $(BINDIR)/$(CLINAME).exe ]; then \
		echo "Error: $(LIBNAME).dll or $(CLINAME).exe not built"; \
		exit 1; \
	fi

# 	make webui
	



cronet-%:
	$(MAKE) ARCH=$* build-cronet

build-cronet:
# 	rm -rf $(CRONET_DIR)
	git init $(CRONET_DIR) || echo "dir exist"
	cd $(CRONET_DIR) && \
	git remote add origin https://github.com/sagernet/cronet-go.git ||echo "remote exist"; \
	git fetch --depth=1 origin $(CRONET_GO_VERSION) && \
	git checkout FETCH_HEAD && \
	git submodule update --init --recursive --depth=1 && \
	if [ "$${VARIANT}" = "musl" ]; then \
		go run ./cmd/build-naive --target=linux/$(ARCH) --libc=musl download-toolchain && \
		go run ./cmd/build-naive --target=linux/$(ARCH) --libc=musl env > cronet.env; \
	else \
		go run ./cmd/build-naive --target=linux/$(ARCH) download-toolchain && \
		go run ./cmd/build-naive --target=linux/$(ARCH) env > cronet.env; \
	fi

################################
# Generic Linux Builder
################################
linux-%:
	$(MAKE) ARCH=$* build-linux

define load_cronet_env
set -a; \
while IFS= read -r line; do \
    key=$${line%%=*}; \
    value=$${line#*=}; \
    export "$$key=$$value"; \
	echo "$$key=$$value"; \
done < $(CRONET_DIR)/cronet.env; \
set +a;
endef

build-linux: prepare
	mkdir -p $(BINDIR)/lib

	$(load_cronet_env)
	FINAL_TAGS=$(TAGS); \
	if [ "$${VARIANT}" = "musl" ]; then \
		FINAL_TAGS=$${FINAL_TAGS},with_musl; \
	elif [ "$${VARIANT}" = "purego" ]; then \
		FINAL_TAGS="$${FINAL_TAGS},with_purego"; \
	fi; \
	echo "FinalTags: $$FINAL_TAGS"; \
	GOOS=linux GOARCH=$(ARCH) $(GOBUILDLIB) -tags $${FINAL_TAGS} -o $(BINDIR)/lib/$(LIBNAME).so ./platform/desktop ;\
	
	echo "Core library built, now building CLI with CGO linking to core library"
	GOOS=linux GOARCH=$(ARCH) CGO_LDFLAGS="$(BINDIR)/lib/$(LIBNAME).so -Wl,-rpath,\$$ORIGIN/lib -fuse-ld=lld" $(GOBUILDSRV) -o $(BINDIR)/$(CLINAME) ./cmd/bydll
	chmod +x $(BINDIR)/$(CLINAME)
	if [ ! -f $(BINDIR)/lib/$(LIBNAME).so -o ! -f $(BINDIR)/$(CLINAME) ]; then \
		echo "Error: $(LIBNAME).so or $(CLINAME) not built"; \
		ls -R $(BINDIR); \
		exit 1; \
	fi
# 	make webui


linux-custom: prepare  install_cronet
	mkdir -p $(BINDIR)/
	#env GOARCH=mips $(GOBUILDSRV) -o $(BINDIR)/$(CLINAME) ./cmd/
	$(load_cronet_env)
	go build -ldflags="$(LDFLAGS)" -trimpath -tags $(TAGS) -o $(BINDIR)/$(CLINAME) ./cmd/main
	chmod +x $(BINDIR)/$(CLINAME)
	make webui

macos-amd64:
	env GOOS=darwin GOARCH=amd64 CGO_CFLAGS="-mmacosx-version-min=10.11 -O2" CGO_LDFLAGS="-mmacosx-version-min=10.11 -O2 -lpthread" CGO_ENABLED=1 go build -trimpath -tags $(TAGS),$(MACOS_ADD_TAGS) -buildmode=c-shared -o $(BINDIR)/$(LIBNAME)-amd64.dylib ./platform/desktop
macos-arm64:
	env GOOS=darwin GOARCH=arm64 CGO_CFLAGS="-mmacosx-version-min=10.11 -O2" CGO_LDFLAGS="-mmacosx-version-min=10.11 -O2 -lpthread" CGO_ENABLED=1 go build -trimpath -tags $(TAGS),$(MACOS_ADD_TAGS) -buildmode=c-shared -o $(BINDIR)/$(LIBNAME)-arm64.dylib ./platform/desktop
	
macos: prepare macos-amd64 macos-arm64 
	
	lipo -create $(BINDIR)/$(LIBNAME)-amd64.dylib $(BINDIR)/$(LIBNAME)-arm64.dylib -output $(BINDIR)/$(LIBNAME).dylib
	mv $(BINDIR)/$(LIBNAME)-arm64.h $(BINDIR)/desktop.h 
	# env GOOS=darwin GOARCH=amd64 CGO_CFLAGS="-mmacosx-version-min=10.15" CGO_LDFLAGS="-mmacosx-version-min=10.15" CGO_LDFLAGS="bin/$(LIBNAME).dylib"  CGO_ENABLED=1 $(GOBUILDSRV)  -o $(BINDIR)/$(CLINAME) ./cmd/bydll
	# rm ./$(LIBNAME).dylib
	# chmod +x $(BINDIR)/$(CLINAME)

prepare: 
	go mod tidy

clean:
	rm -f $(LIBNAME).dll $(LIBNAME).dylib
	rm -rf $(BINDIR)/*




.PHONY: release
release: # Create a new tag for release.	
	@bash -c '.github/change_version.sh'
	


