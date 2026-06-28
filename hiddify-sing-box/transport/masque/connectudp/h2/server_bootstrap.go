package h2

import (
	"net"
	"net/http"
)

// RegisterDownloadBeforeOK registers an asymmetric download leg before HTTP 200 (closes TOCTOU vs HasActiveDownload).
func RegisterDownloadBeforeOK(w http.ResponseWriter, r *http.Request, conn *net.UDPConn, targetAddr string, reg *SessionRegistry) error {
	if StreamRoleFromRequest(r) != StreamRoleDownload || conn == nil {
		return nil
	}
	key, err := RequireSessionKey(r, targetAddr)
	if err != nil {
		return err
	}
	downlinkW := NewDownlinkResponseWriter(w)
	_, err = reg.RegisterDownload(key, conn, downlinkW)
	return err
}
