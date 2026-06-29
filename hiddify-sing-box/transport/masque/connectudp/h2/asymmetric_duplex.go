package h2

// AsymmetricDuplexConfigured enables split download-primary + upload-pool CONNECT-UDP legs (prod: on).
func AsymmetricDuplexConfigured() bool {
	return ConnectUDPDialPolicyFromEnv().AsymmetricDuplex
}

type streamRole uint8

const (
	streamRoleBidi streamRole = iota
	streamRoleDownload
	streamRoleUpload
)

func streamRoleHeader(role streamRole) string {
	switch role {
	case streamRoleDownload:
		return StreamRoleDownload
	case streamRoleUpload:
		return StreamRoleUpload
	default:
		return ""
	}
}
