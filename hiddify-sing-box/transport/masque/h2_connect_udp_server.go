package masque

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"syscall"

	"github.com/quic-go/quic-go/quicvarint"
)

func isServeH2ConnectUDPTerminalConnErr(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
		return true
	}
	for e := err; e != nil; e = errors.Unwrap(e) {
		var errno syscall.Errno
		if errors.As(e, &errno) {
			switch errno {
			case syscall.ECONNREFUSED, syscall.EHOSTUNREACH, syscall.ENETUNREACH,
				syscall.ECONNRESET, syscall.ENETRESET:
				return true
			}
		}
	}
	s := strings.ToLower(err.Error())
	return strings.Contains(s, "use of closed network connection") ||
		strings.Contains(s, "pipe is being closed") ||
		strings.Contains(s, "connection refused") ||
		strings.Contains(s, "host unreachable") ||
		strings.Contains(s, "network unreachable") ||
		strings.Contains(s, "no route to host")
}

// ServeH2ConnectUDP relays UDP payloads over an established HTTP/2 CONNECT-UDP stream using
// RFC 9297 DATAGRAM capsules (same wire format as dialUDPOverHTTP2 on the client).
// The caller must set response headers and WriteHeader(http.StatusOK) before calling this.
func ServeH2ConnectUDP(w http.ResponseWriter, r *http.Request, conn *net.UDPConn) error {
	if w == nil || r == nil || conn == nil {
		return errors.New("masque h2: connect-udp relay: nil argument")
	}
	flusher, _ := w.(http.Flusher)

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
	wg.Add(2)
	go func() {
		defer wg.Done()
		defer shutdownRelay()
		defer closeUDPConn()
		br := bufio.NewReader(r.Body)
		for {
			ct, cr, err := parseH2ConnectUDPCapsule(quicvarint.NewReader(br))
			if err != nil {
				if errors.Is(err, io.EOF) {
					return
				}
				upErr = fmt.Errorf("masque h2 dataplane connect-udp server capsule: %w", err)
				return
			}
			if ct != capsuleTypeDatagram {
				if _, err := io.Copy(io.Discard, cr); err != nil {
					upErr = fmt.Errorf("masque h2 dataplane connect-udp server non-datagram capsule drain: %w", err)
					return
				}
				continue
			}
			payload, err := io.ReadAll(cr)
			if err != nil {
				upErr = fmt.Errorf("masque h2 dataplane connect-udp server capsule body: %w", err)
				return
			}
			udpPayload, ok, perr := ParseMasqueHTTPDatagramUDP(payload)
			// Match client / H3: drop malformed HTTP Datagram payloads without failing the relay.
			if perr != nil || !ok {
				continue
			}
			if _, err := conn.Write(udpPayload); err != nil {
				upErr = fmt.Errorf("masque h2 dataplane connect-udp server udp write: %w", err)
				return
			}
		}
	}()
	go func() {
		defer wg.Done()
		defer shutdownRelay()
		defer closeUDPConn()
		buf := make([]byte, h2ConnectUDPServerUDPReadBuf)
		for {
			n, err := conn.Read(buf)
			if err != nil {
				if isServeH2ConnectUDPTerminalConnErr(err) {
					return
				}
				downErr = fmt.Errorf("masque h2 dataplane connect-udp server udp read: %w", err)
				return
			}
			if err := writeUDPPayloadAsH2DatagramCapsules(w, flusher, buf[:n]); err != nil {
				downErr = fmt.Errorf("masque h2 dataplane connect-udp server down capsule: %w", err)
				return
			}
		}
	}()
	wg.Wait()
	joined := errors.Join(upErr, downErr)
	_ = http.NewResponseController(w).Flush()
	return joined
}
