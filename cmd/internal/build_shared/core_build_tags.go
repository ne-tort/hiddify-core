package build_shared

import "strings"

// CoreSingBoxBaseTags — Linux/desktop server и общая база sing-box в hiddify-core.
func CoreSingBoxBaseTags() []string {
	return []string{
		"with_gvisor",
		"with_quic",
		"with_wireguard",
		"with_awg",
		"with_l3router",
		"with_utls",
		"with_clash_api",
		"with_grpc",
		"with_acme",
		"with_masque",
		"with_conntrack",
		"badlinkname",
		"tfogo_checklinkname0",
		"with_tailscale",
		"ts_omit_logtail",
		"ts_omit_ssh",
		"ts_omit_drive",
		"ts_omit_taildrop",
		"ts_omit_webclient",
		"ts_omit_doctor",
		"ts_omit_capture",
		"ts_omit_kube",
		"ts_omit_aws",
		"ts_omit_synology",
		"ts_omit_bird",
	}
}

// CoreSingBoxTagsWindows — Windows client (libcronet / CGO): base + naive + purego.
func CoreSingBoxTagsWindows() []string {
	tags := append([]string{}, CoreSingBoxBaseTags()...)
	tags = append(tags, "with_naive_outbound", "with_purego")
	return tags
}

// JoinBuildTags comma-separated for -tags.
func JoinBuildTags(tags []string) string {
	return strings.Join(tags, ",")
}
