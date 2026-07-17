package h2

import (
	"errors"
	"io"
	"net"
	"net/http"
	"sync"

	cudprelay "github.com/sagernet/sing-box/transport/masque/connectudp/relay"
)

// ServeH2FromRequest relays CONNECT-UDP. When Masque-Udp-Stream-Role is set, routes asymmetric legs
// through a scoped H2Session registry; otherwise delegates to full-duplex ServeH2.
func ServeH2FromRequest(w http.ResponseWriter, r *http.Request, conn *net.UDPConn, targetAddr string, reg *SessionRegistry) error {
	role := StreamRoleFromRequest(r)
	if role == "" {
		return ServeH2(w, r, conn)
	}
	key, err := RequireSessionKey(r, targetAddr)
	if err != nil {
		return err
	}
	switch role {
	case StreamRoleDownload:
		return serveH2DownloadLeg(w, r, conn, key, reg)
	case StreamRoleUpload:
		if conn != nil {
			_ = conn.Close()
		}
		return serveH2UploadLeg(w, r, key, reg)
	default:
		return errors.New("masque h2: unknown CONNECT-UDP stream role")
	}
}

func serveH2DownloadLeg(w http.ResponseWriter, r *http.Request, conn *net.UDPConn, key sessionKey, reg *SessionRegistry) error {
	if w == nil || r == nil || conn == nil {
		return errors.New("masque h2: asymmetric download leg: nil argument")
	}
	defer cudprelay.BeginRelaySessionStats("h2-download-leg")()
	sess, downlinkW, ok := reg.lookupDownloadSession(key)
	if !ok {
		downlinkW = newH2DownlinkWriter(w, LegProfileDownloadFountain)
		var err error
		sess, err = reg.RegisterDownload(key, conn, downlinkW)
		if err != nil {
			_ = conn.Close()
			return err
		}
	}
	defer reg.Release(key)

	var wg sync.WaitGroup
	var closeUDP sync.Once
	closeUDPConn := func() { closeUDP.Do(func() { _ = conn.Close() }) }
	var shutdownBody sync.Once
	shutdownRelay := func() {
		shutdownBody.Do(func() {
			if r.Body != nil {
				_ = r.Body.Close()
			}
		})
	}

	var downErr error

	go func() {
		<-r.Context().Done()
		closeUDPConn()
		shutdownRelay()
	}()

	wg.Add(2)
	// Asymmetric download: S2C only. C2S capsules belong on the upload leg (H3 download-leg parity).
	go func() {
		defer wg.Done()
		defer shutdownRelay()
		_, _ = io.Copy(io.Discard, r.Body)
	}()
	go func() {
		defer wg.Done()
		defer shutdownRelay()
		defer closeUDPConn()
		select {
		case <-sess.ready:
		case <-r.Context().Done():
			return
		}
		// Asymmetric download: S2C-only leg — batch append + threshold flush (fountain KPI; no echo on this stream).
		downErr = cudprelay.RelayH2ConnectDownlinkFountain(r.Context(), conn, H2ServerUDPReadBuf, downlinkW)
	}()
	wg.Wait()
	_ = http.NewResponseController(w).Flush()
	return downErr
}

func serveH2UploadLeg(w http.ResponseWriter, r *http.Request, key sessionKey, reg *SessionRegistry) error {
	if w == nil || r == nil {
		return errors.New("masque h2: asymmetric upload leg: nil argument")
	}
	defer cudprelay.BeginRelaySessionStats("h2-upload-leg")()
	sess, err := reg.AttachUpload(key)
	if err != nil {
		return err
	}
	defer reg.Release(key)

	var shutdownBody sync.Once
	shutdownRelay := func() {
		shutdownBody.Do(func() {
			if r.Body != nil {
				_ = r.Body.Close()
			}
		})
	}

	signalReady := func() { sess.signalReady() }
	onward := sess.onwardWriter()
	onICMP := func() error { return sess.writeDownlinkICMP() }

	if err := sess.waitReady(r.Context().Done()); err != nil {
		return err
	}

	go func() {
		<-r.Context().Done()
		shutdownRelay()
	}()

	defer shutdownRelay()
		// Asymmetric upload: masque-go OnwardUDPWriter WriteBatch (perf); h2o uses per-packet send on bidi only.
		return cudprelay.RelayH2ConnectUplink(r, onward, H2ResponseBodyBufSize, signalReady, onICMP)
}
