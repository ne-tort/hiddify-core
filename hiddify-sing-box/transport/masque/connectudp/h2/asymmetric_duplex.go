package h2

import (
	"os"
	"strconv"
	"strings"
)

const envH2ConnectUDPAsymmetricDuplex = "MASQUE_H2_CONNECT_UDP_ASYMMETRIC_DUPLEX"

// AsymmetricDuplexConfigured enables split download-primary + upload-pool CONNECT-UDP legs (default on).
func AsymmetricDuplexConfigured() bool {
	v := strings.TrimSpace(os.Getenv(envH2ConnectUDPAsymmetricDuplex))
	if v == "" {
		return true
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return true
	}
	return b
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
