package relay

import (
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"sync"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/quic-go/quicvarint"
	cudpasym "github.com/sagernet/sing-box/transport/masque/connectudp/asym"
	connectudp "github.com/sagernet/sing-box/transport/masque/connectudp"
	"github.com/sagernet/sing-box/transport/masque/connectudp/frame"
)

// ServeH3Asymmetric routes CONNECT-UDP over HTTP/3 with Masque-Udp-Stream-Role legs (UDP-5p2b).
func ServeH3Asymmetric(w http.ResponseWriter, r *http.Request, parsed *frame.Request, reg *H3SessionRegistry) error {
	if reg == nil {
		reg = DefaultH3SessionRegistry
	}
	role := cudpasym.StreamRoleFromRequest(r)
	if role == "" {
		return errors.New("connectudp/relay: h3 asymmetric serve without stream role")
	}
	key, err := h3SessionKeyFromHTTP(r, parsed.Target)
	if err != nil {
		return err
	}
	streamer, ok := w.(http3.HTTPStreamer)
	if !ok {
		return errors.New("connectudp/relay: h3 asymmetric response writer is not http3.HTTPStreamer")
	}
	str := streamer.HTTPStream()

	switch role {
	case cudpasym.StreamRoleDownload:
		return serveH3DownloadLeg(w, r, str, parsed, key, reg)
	case cudpasym.StreamRoleUpload:
		return serveH3UploadLeg(w, r, str, key, reg)
	default:
		return errors.New("connectudp/relay: unknown h3 asymmetric stream role")
	}
}

func serveH3DownloadLeg(w http.ResponseWriter, r *http.Request, str *http3.Stream, parsed *frame.Request, key h3SessionKey, reg *H3SessionRegistry) error {
	addr, err := net.ResolveUDPAddr("udp", parsed.Target)
	if err != nil {
		w.WriteHeader(connectudp.ResolveDialToHTTPStatus(err))
		return err
	}
	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		w.WriteHeader(connectudp.ResolveDialToHTTPStatus(err))
		return err
	}
	tuneMasqueUDPSocketBuffers(conn)

	if _, err := reg.RegisterH3Download(key, conn); err != nil {
		_ = conn.Close()
		if errors.Is(err, ErrDuplicateH3DownloadSession) {
			w.WriteHeader(http.StatusConflict)
		} else {
			w.WriteHeader(http.StatusInternalServerError)
		}
		return err
	}
	defer reg.ReleaseH3(key)

	w.Header().Set(http3.CapsuleProtocolHeader, frame.CapsuleProtocolHeaderValue)
	w.WriteHeader(http.StatusOK)

	var closeStream sync.Once
	var closeUDP sync.Once
	shutdownStream := func() {
		closeStream.Do(func() {
			str.CancelRead(quic.StreamErrorCode(http3.ErrCodeConnectError))
			_ = str.Close()
		})
	}
	shutdownUDP := func() { closeUDP.Do(func() { _ = conn.Close() }) }
	defer shutdownStream()
	defer shutdownUDP()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer shutdownStream()
		if err := proxyConnReceive(conn, str); err != nil {
			log.Printf("h3 asymmetric download-leg S2C relay from %s failed: %v", conn.RemoteAddr(), err)
		}
	}()

	if err := frame.SkipRequestStreamCapsules(quicvarint.NewReader(str)); err != nil && !errors.Is(err, io.EOF) {
		log.Printf("h3 asymmetric download skip capsules: %v", err)
	}
	shutdownStream()
	shutdownUDP()
	wg.Wait()
	return nil
}

func serveH3UploadLeg(w http.ResponseWriter, r *http.Request, str *http3.Stream, key h3SessionKey, reg *H3SessionRegistry) error {
	sess, err := reg.AttachH3Upload(key)
	if err != nil {
		w.WriteHeader(http.StatusBadGateway)
		return err
	}
	defer reg.ReleaseH3(key)

	conn := sess.sharedConn()
	if conn == nil {
		w.WriteHeader(http.StatusBadGateway)
		return errors.New("masque h3: asymmetric upload leg without shared UDP conn")
	}
	if err := sess.waitReady(r.Context().Done()); err != nil {
		w.WriteHeader(http.StatusBadGateway)
		return err
	}

	w.Header().Set(http3.CapsuleProtocolHeader, frame.CapsuleProtocolHeaderValue)
	w.WriteHeader(http.StatusOK)

	var closeStream sync.Once
	shutdownStream := func() {
		closeStream.Do(func() {
			str.CancelRead(quic.StreamErrorCode(http3.ErrCodeConnectError))
			_ = str.Close()
		})
	}
	defer shutdownStream()

	relay := &Proxy{}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer shutdownStream()
		if err := relay.proxyConnSend(r.Context(), conn, str); err != nil {
			log.Printf("h3 asymmetric upload-only relay failed: %v", err)
		}
	}()

	if err := frame.SkipRequestStreamCapsules(quicvarint.NewReader(str)); err != nil && !errors.Is(err, io.EOF) {
		log.Printf("h3 asymmetric upload skip capsules: %v", err)
	}
	shutdownStream()
	wg.Wait()
	return nil
}
