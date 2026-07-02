package h2

import (
	"fmt"
	"net"
	"net/http"
	"time"
)

// WaitDownloadSessionBeforeOK blocks upload legs until the matching download session is registered.
func WaitDownloadSessionBeforeOK(r *http.Request, targetAddr string, reg *SessionRegistry) error {
	if StreamRoleFromRequest(r) != StreamRoleUpload {
		return nil
	}
	key, err := RequireSessionKey(r, targetAddr)
	if err != nil {
		return err
	}
	if reg == nil {
		reg = DefaultSessionRegistry
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		reg.mu.Lock()
		sess, ok := reg.sessions[key]
		reg.mu.Unlock()
		if ok && sess != nil {
			sess.mu.Lock()
			ready := sess.downlinkOK && sess.conn != nil
			sess.mu.Unlock()
			if ready {
				return nil
			}
		}
		time.Sleep(time.Millisecond)
	}
	return fmt.Errorf("masque h2: asymmetric upload leg timed out waiting for download session target=%s", key.target)
}

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
