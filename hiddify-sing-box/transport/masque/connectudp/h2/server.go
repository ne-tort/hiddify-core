package h2

import (
	"context"
	"errors"
	"net"
	"net/http"
	"sync"

	cudprelay "github.com/sagernet/sing-box/transport/masque/connectudp/relay"
	h2c "github.com/sagernet/sing-box/transport/masque/h2"
)

const (
	H2ServerUDPReadBuf    = 65535
	H2ResponseBodyBufSize = 256 * 1024
	// H2DownlinkBulkFlushBytes batches S2C RFC9297 wire before one HTTP/2 flush (capsule.go batch + G42).
	H2DownlinkBulkFlushBytes = 32 * 1024
)

// H2ResponseWriter writes DATAGRAM capsules on the CONNECT-UDP response body.
// Fountain: relay UDP drain + Append* with byte threshold flush. ICMP/bidi Write: h2o 1:1 immediate.
type H2ResponseWriter struct {
	http.ResponseWriter
	profile           LegProfile
	mu                sync.Mutex
	pendingSinceFlush int
}

func (w *H2ResponseWriter) WriteUDPPayloadAsCapsules(udpPayload []byte) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.writeCapsulesImmediateLocked(udpPayload)
}

// AppendUDPPayloadAsCapsules appends RFC9297 wire; flushes at H2DownlinkBulkFlushBytes (no debounce timer).
func (w *H2ResponseWriter) AppendUDPPayloadAsCapsules(udpPayload []byte) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if len(udpPayload) == 0 {
		return w.writeCapsulesImmediateLocked(nil)
	}
	if err := w.appendCapsulesLocked(udpPayload); err != nil {
		return err
	}
	if w.pendingSinceFlush >= H2DownlinkBulkFlushBytes {
		return w.flushLocked()
	}
	return nil
}

func (w *H2ResponseWriter) appendCapsulesLocked(udpPayload []byte) error {
	if len(udpPayload) <= h2c.MaxUDPPayloadPerDatagramCapsule() {
		if err := h2c.AppendDatagramCapsuleWire(w.ResponseWriter, udpPayload); err != nil {
			return err
		}
	} else if err := h2c.AppendUDPPayloadAsDatagramCapsules(w.ResponseWriter, udpPayload); err != nil {
		return err
	}
	w.pendingSinceFlush += h2c.UDPPayloadWireLen(udpPayload)
	return nil
}

func (w *H2ResponseWriter) writeCapsulesImmediateLocked(udpPayload []byte) error {
	w.pendingSinceFlush = 0
	if len(udpPayload) <= h2c.MaxUDPPayloadPerDatagramCapsule() {
		return h2c.WriteDatagramCapsule(w.ResponseWriter, udpPayload)
	}
	return h2c.WriteUDPPayloadAsDatagramCapsules(w.ResponseWriter, udpPayload)
}

func (w *H2ResponseWriter) flushLocked() error {
	h2c.FlushResponse(w.ResponseWriter)
	w.pendingSinceFlush = 0
	return nil
}

func (w *H2ResponseWriter) FlushPending() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.pendingSinceFlush <= 0 {
		return nil
	}
	return w.flushLocked()
}

func newH2DownlinkWriter(w http.ResponseWriter, profile LegProfile) *H2ResponseWriter {
	return &H2ResponseWriter{ResponseWriter: w, profile: profile}
}

func NewDownlinkResponseWriter(w http.ResponseWriter) *H2ResponseWriter {
	return newH2DownlinkWriter(w, LegProfileDownloadFountain)
}

// ServeH2 relays UDP over HTTP/2 CONNECT-UDP (h2o event-loop semantics: 2 goroutines).
func ServeH2(w http.ResponseWriter, r *http.Request, conn *net.UDPConn) error {
	if w == nil || r == nil || conn == nil {
		return errors.New("masque h2: connect-udp relay: nil argument")
	}
	downlinkW := newH2DownlinkWriter(w, LegProfileBidi)
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
	downlinkReady := make(chan struct{})
	var downlinkReadyOnce sync.Once
	signalDownlinkReady := func() {
		downlinkReadyOnce.Do(func() { close(downlinkReady) })
	}
	signalDownlinkReady()
	onward := &cudprelay.DirectH2OnwardWriter{W: cudprelay.NewOnwardUDPWriter(conn)}
	onICMP := func() error { return downlinkW.WriteUDPPayloadAsCapsules(nil) }

	relayCtx, cancelRelay := context.WithCancel(r.Context())
	defer cancelRelay()

	wg.Add(2)
	go func() {
		defer wg.Done()
		defer shutdownRelay()
		defer closeUDPConn()
		defer cancelRelay()
		upErr = cudprelay.RelayH2ConnectUplink(r, onward, H2ResponseBodyBufSize, signalDownlinkReady, onICMP)
	}()
	go func() {
		defer wg.Done()
		defer shutdownRelay()
		defer closeUDPConn()
		defer func() { _ = downlinkW.FlushPending() }()
		select {
		case <-downlinkReady:
		case <-relayCtx.Done():
			return
		}
		// h2o connect.c: flush S2C after each onward UDP drain batch (bidi echo path).
		downErr = cudprelay.RelayH2ConnectDownlink(relayCtx, conn, H2ServerUDPReadBuf, downlinkW, H2DownlinkBulkFlushBytes, func(payloads [][]byte) bool {
			return true
		})
	}()
	wg.Wait()
	joined := errors.Join(upErr, downErr)
	_ = http.NewResponseController(w).Flush()
	return joined
}
