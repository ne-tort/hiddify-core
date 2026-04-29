package build_shared

import "strings"

// Hiddify sing-box / libbox feature parity for the Hiddify client (desktop DLL, gomobile).
// Mirrors hiddify-sing-box/cmd/internal/build_libbox sharedTags + desktop extras (with_grpc, with_acme). Do not use with_ech (deprecated stub in sing-box).
//
// When changing tags, update consumers (or run from repo root: go run ./hiddify-core/cmd/print_core_build_tags …):
//   hiddify-core: build_windows.bat, cmd.bat, cmd/internal/build_libcore/main.go
//   vendor/s-ui: build.sh, Dockerfile, windows/build-windows.ps1, .github/workflows/{windows,release}.yml

var tailscaleOmitTags = []string{
	"ts_omit_logtail", "ts_omit_ssh", "ts_omit_drive", "ts_omit_taildrop",
	"ts_omit_webclient", "ts_omit_doctor", "ts_omit_capture", "ts_omit_kube",
	"ts_omit_aws", "ts_omit_synology", "ts_omit_bird",
}

// CoreSingBoxBaseTags is used for Linux/macOS desktop builds and gomobile (no with_purego).
// Windows appends with_purego (see CoreSingBoxTagsWindows) so cronet/naive loads the bundled libcronet.
func CoreSingBoxBaseTags() []string {
	t := []string{
		"with_gvisor", "with_quic", "with_wireguard", "with_awg", "with_l3router", "with_masque",
		"with_utls", "with_clash_api", "with_grpc", "with_acme",
		"with_naive_outbound", "with_conntrack", "badlinkname", "tfogo_checklinkname0",
		"with_tailscale",
	}
	t = append(t, tailscaleOmitTags...)
	return t
}

// CoreSingBoxTagsWindows is CoreSingBoxBaseTags + with_purego (required for naive on Windows).
func CoreSingBoxTagsWindows() []string {
	return append(CoreSingBoxBaseTags(), "with_purego")
}

// JoinBuildTags is the comma-separated -tags value.
func JoinBuildTags(tags []string) string {
	return strings.Join(tags, ",")
}
