package h2

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
