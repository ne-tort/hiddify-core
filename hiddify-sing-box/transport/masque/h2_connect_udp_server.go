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

// isServeH2ConnectUDPTransientReadErr mirrors third_party/masque-go proxyConnReceive: ICMP errors
// and other socket pressure on a connected UDP relay socket (e.g. dig to a TCP-only port →
// ECONNREFUSED on Read) must not tear down the HTTP/2 CONNECT-UDP downlink; H3 path already stays up.
func isServeH2ConnectUDPTransientReadErr(err error) bool {
	if err == nil {
		return false
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return true
	}
	return errors.Is(err, syscall.EAGAIN) ||
		errors.Is(err, syscall.EWOULDBLOCK) ||
		errors.Is(err, syscall.ENOBUFS) ||
		errors.Is(err, syscall.EINTR) ||
		errors.Is(err, syscall.ECONNREFUSED) ||
		errors.Is(err, syscall.ECONNRESET)
}

// isServeH2ConnectUDPTransientWriteErr mirrors masque-go isTransientUDPSendError for best-effort
// CONNECT-UDP uplink (drop one datagram, keep session).
func isServeH2ConnectUDPTransientWriteErr(err error) bool {
	if err == nil {
		return false
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return true
	}
	return errors.Is(err, syscall.EAGAIN) ||
		errors.Is(err, syscall.EWOULDBLOCK) ||
		errors.Is(err, syscall.ENOBUFS) ||
		errors.Is(err, syscall.EINTR) ||
		errors.Is(err, syscall.ECONNRESET)
}

// isServeH2ConnectUDPICMPUnreachableRead reports connected-UDP reads where the kernel delivered
// ICMP destination-unreachable (e.g. dig to a TCP-only port) with no payload. masque-go keeps the
// H3 session alive by treating these as transient; for H2 we relay an empty RFC 9297 DATAGRAM so
// the client ReadFrom unblocks (bench UDP probe expects delivery, not a silent drop).
func isServeH2ConnectUDPICMPUnreachableRead(n int, err error) bool {
	if err == nil {
		return false
	}
	// Connected UDP may surface ICMP port-unreachable with n>0 on some kernels; never forward
	// those bytes as a DATAGRAM capsule (bench dig sees "short (< header size) message").
	return errors.Is(err, syscall.ECONNREFUSED) ||
		errors.Is(err, syscall.EHOSTUNREACH) ||
		errors.Is(err, syscall.ENETUNREACH)
}

func isServeH2ConnectUDPTerminalConnErr(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
		return true
	}
	s := strings.ToLower(err.Error())
	return strings.Contains(s, "use of closed network connection") ||
		strings.Contains(s, "pipe is being closed")
}

// h2ConnectUDPResponseWriter serializes downlink capsule writes + flush (connect-ip-go h2ServerCapsuleStream parity).
type h2ConnectUDPResponseWriter struct {
	http.ResponseWriter
	mu sync.Mutex
}

func (w *h2ConnectUDPResponseWriter) writeUDPPayloadAsCapsules(udpPayload []byte) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if err := writeUDPPayloadAsH2DatagramCapsules(w.ResponseWriter, udpPayload); err != nil {
		return err
	}
	// connect-ip-go h2ServerCapsuleStream flushes after every Write/SendDatagram; ensure each
	// downlink capsule (including ICMP empty DATAGRAM) leaves the server before the next Read.
	flushH2ConnectUDPResponse(w.ResponseWriter)
	return nil
}

// ServeH2ConnectUDP relays UDP payloads over an established HTTP/2 CONNECT-UDP stream using
// RFC 9297 DATAGRAM capsules (same wire format as dialUDPOverHTTP2 on the client).
// The caller must set response headers and WriteHeader(http.StatusOK) before calling this.
func ServeH2ConnectUDP(w http.ResponseWriter, r *http.Request, conn *net.UDPConn) error {
	if w == nil || r == nil || conn == nil {
		return errors.New("masque h2: connect-udp relay: nil argument")
	}
	downlinkW := &h2ConnectUDPResponseWriter{ResponseWriter: w}
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
	// Client starts the response-body pump before the first uplink WriteTo; unblock the onward UDP
	// recv loop immediately. Downlink still only writes capsules after kernel Read (no early Write
	// before the peer consumes the response stream — avoids H2 flow-control stall vs bench dig).
	downlinkReady := make(chan struct{})
	var downlinkReadyOnce sync.Once
	signalDownlinkReady := func() {
		downlinkReadyOnce.Do(func() { close(downlinkReady) })
	}
	signalDownlinkReady()
	wg.Add(2)
	go func() {
		defer wg.Done()
		defer shutdownRelay()
		defer closeUDPConn()
		br := bufio.NewReaderSize(r.Body, h2ConnectUDPResponseBodyBufSize)
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
			// Zero-length RFC 9297 DATAGRAM (context id only) is a stream prime / keepalive — do not
			// Write to the onward UDP socket (connected sockets may reject it and stall downlinkReady).
			if len(udpPayload) == 0 {
				signalDownlinkReady()
				continue
			}
			if _, err := conn.Write(udpPayload); err != nil {
				// Connected UDP surfaces ICMP port-unreachable on Write on Linux (bench dig to TCP-only port).
				if errors.Is(err, syscall.ECONNREFUSED) ||
					errors.Is(err, syscall.EHOSTUNREACH) ||
					errors.Is(err, syscall.ENETUNREACH) {
					if werr := downlinkW.writeUDPPayloadAsCapsules(nil); werr != nil {
						downErr = fmt.Errorf("masque h2 dataplane connect-udp server icmp empty dgram after write: %w", werr)
						return
					}
					continue
				}
				if isServeH2ConnectUDPTransientWriteErr(err) {
					continue
				}
				upErr = fmt.Errorf("masque h2 dataplane connect-udp server udp write: %w", err)
				return
			}
			signalDownlinkReady()
		}
	}()
	go func() {
		defer wg.Done()
		defer shutdownRelay()
		defer closeUDPConn()
		select {
		case <-downlinkReady:
		case <-r.Context().Done():
			return
		}
		buf := make([]byte, h2ConnectUDPServerUDPReadBuf)
		for {
			n, err := conn.Read(buf)
			if err != nil {
				if isServeH2ConnectUDPICMPUnreachableRead(n, err) {
					if werr := downlinkW.writeUDPPayloadAsCapsules(nil); werr != nil {
						downErr = fmt.Errorf("masque h2 dataplane connect-udp server icmp empty dgram: %w", werr)
						return
					}
					continue
				}
				if isServeH2ConnectUDPTransientReadErr(err) {
					continue
				}
				if isServeH2ConnectUDPTerminalConnErr(err) {
					return
				}
				downErr = fmt.Errorf("masque h2 dataplane connect-udp server udp read: %w", err)
				return
			}
			if err := downlinkW.writeUDPPayloadAsCapsules(buf[:n]); err != nil {
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
