package h2

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"

	"github.com/sagernet/sing-box/transport/masque/connectudp/frame"
	h2c "github.com/sagernet/sing-box/transport/masque/h2"
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
		return ServeH2(w, r, conn)
	}
}

func serveH2DownloadLeg(w http.ResponseWriter, r *http.Request, conn *net.UDPConn, key sessionKey, reg *SessionRegistry) error {
	if w == nil || r == nil || conn == nil {
		return errors.New("masque h2: asymmetric download leg: nil argument")
	}
	downlinkW := newH2DownlinkWriter(w, LegProfileDownloadFountain)
	sess, err := reg.RegisterDownload(key, conn, downlinkW)
	if err != nil {
		_ = conn.Close()
		return err
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

	var upErr, downErr error
	signalReady := func() { sess.signalReady() }
	onward := sess.onwardWriter()
	onICMP := func() error { return downlinkW.WriteUDPPayloadAsCapsules(nil) }

	wg.Add(2)
	go func() {
		defer wg.Done()
		defer shutdownRelay()
		defer closeUDPConn()
		upErr = relayH2ConnectUplink(r, onward, signalReady, onICMP)
	}()
	go func() {
		defer wg.Done()
		defer shutdownRelay()
		defer closeUDPConn()
		defer func() { _ = downlinkW.FlushPending() }()
		select {
		case <-sess.ready:
		case <-r.Context().Done():
			return
		}
		downErr = relayH2ConnectDownlink(r.Context(), conn, downlinkW)
	}()
	wg.Wait()
	joined := errors.Join(upErr, downErr)
	_ = http.NewResponseController(w).Flush()
	return joined
}

func serveH2UploadLeg(w http.ResponseWriter, r *http.Request, key sessionKey, reg *SessionRegistry) error {
	if w == nil || r == nil {
		return errors.New("masque h2: asymmetric upload leg: nil argument")
	}
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
	defer shutdownRelay()

	signalReady := func() { sess.signalReady() }
	onward := sess.onwardWriter()
	onICMP := func() error { return sess.writeDownlinkICMP() }

	if err := sess.waitReady(r.Context().Done()); err != nil {
		return err
	}
	upErr := relayH2ConnectUplink(r, onward, signalReady, onICMP)
	_ = http.NewResponseController(w).Flush()
	return upErr
}

func relayH2ConnectUplink(r *http.Request, onward *sessionOnwardWriter, signalReady func(), onICMP func() error) error {
	br := bufio.NewReaderSize(r.Body, H2ResponseBodyBufSize)
	readBuf := make([]byte, H2ResponseBodyBufSize)
	var pending []byte
	relayOnward := func(payload []byte) error {
		icmp, err := onward.queue(payload)
		if icmp {
			if onICMP != nil {
				if werr := onICMP(); werr != nil {
					return fmt.Errorf("masque h2 dataplane connect-udp server icmp empty dgram after write: %w", werr)
				}
			}
			return nil
		}
		if err != nil {
			return fmt.Errorf("masque h2 dataplane connect-udp server udp write: %w", err)
		}
		if signalReady != nil {
			signalReady()
		}
		return nil
	}
	for {
		for len(pending) > 0 {
			if n512 := h2c.CountLeadingDatagramCapsule512Wire(pending); n512 > 0 {
				wireLen := h2c.DatagramCapsule512WireLen
				icmp, err := onward.sendBurstViews(pending, n512, wireLen, wireLen-512)
				pending = pending[n512*wireLen:]
				if icmp {
					if onICMP != nil {
						if werr := onICMP(); werr != nil {
							return fmt.Errorf("masque h2 dataplane connect-udp server icmp empty dgram after burst: %w", werr)
						}
					}
				} else if err != nil {
					return fmt.Errorf("masque h2 dataplane connect-udp server udp burst: %w", err)
				}
				if signalReady != nil {
					signalReady()
				}
				continue
			}
			if udpPayload, consumed, ok := h2c.TryConsumeDatagramCapsule512Wire(pending); ok {
				pending = pending[consumed:]
				if err := relayOnward(udpPayload); err != nil {
					return err
				}
				continue
			}
			inner, consumed, perr := h2c.ParseNextDatagramCapsuleWire(pending)
			if perr != nil {
				return fmt.Errorf("masque h2 dataplane connect-udp server capsule: %w", perr)
			}
			if consumed == 0 {
				break
			}
			pending = pending[consumed:]
			if inner == nil {
				continue
			}
			udpPayload, ok, uperr := frame.ParseHTTPDatagramUDP(inner)
			if uperr != nil || !ok {
				continue
			}
			if len(udpPayload) == 0 {
				if signalReady != nil {
					signalReady()
				}
				continue
			}
			if err := relayOnward(udpPayload); err != nil {
				return err
			}
		}
		if icmp, err := onward.flush(); err != nil {
			return fmt.Errorf("masque h2 dataplane connect-udp server udp flush: %w", err)
		} else if icmp {
			if onICMP != nil {
				if werr := onICMP(); werr != nil {
					return fmt.Errorf("masque h2 dataplane connect-udp server icmp empty dgram after flush: %w", werr)
				}
			}
		}
		if len(pending) == 0 && cap(pending) > H2ResponseBodyBufSize*2 {
			pending = nil
		}
		nr, err := br.Read(readBuf)
		if nr > 0 {
			pending = append(pending, readBuf[:nr]...)
			continue
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				if len(pending) > 0 {
					return fmt.Errorf("masque h2 dataplane connect-udp server capsule: %w", io.ErrUnexpectedEOF)
				}
				return nil
			}
			return fmt.Errorf("masque h2 dataplane connect-udp server capsule: %w", err)
		}
	}
}

func relayH2ConnectDownlink(ctx context.Context, conn *net.UDPConn, downlinkW *H2ResponseWriter) error {
	buf := make([]byte, H2ServerUDPReadBuf)
	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}
		n, err := conn.Read(buf)
		if err != nil {
			if isH2ServeICMPUnreachableRead(n, err) {
				if werr := downlinkW.WriteUDPPayloadAsCapsules(nil); werr != nil {
					return fmt.Errorf("masque h2 dataplane connect-udp server icmp empty dgram: %w", werr)
				}
				continue
			}
			if isH2ServeTransientReadErr(err) {
				continue
			}
			if isH2ServeTerminalConnErr(err) {
				return nil
			}
			return fmt.Errorf("masque h2 dataplane connect-udp server udp read: %w", err)
		}
		if err := downlinkW.WriteUDPPayloadAsCapsules(buf[:n]); err != nil {
			return fmt.Errorf("masque h2 dataplane connect-udp server down capsule: %w", err)
		}
	}
}
