package h2

import (
	"context"
	"errors"
	"net"
	"net/http"
	"sync"
	"bytes"

	cudprelay "github.com/sagernet/sing-box/transport/masque/connectudp/relay"
	h2c "github.com/sagernet/sing-box/transport/masque/h2"
)

const (
	H2ServerUDPReadBuf    = 65535
	H2ResponseBodyBufSize = 256 * 1024
	// H2DownlinkBulkFlushBytes batches S2C RFC9297 wire before one HTTP/2 flush (capsule.go batch + G42).
	// Matches upload coalesce (h2UploadCoalesceBytes) and readOnwardUDPBatch wire budget.
	H2DownlinkBulkFlushBytes = 64 * 1024
)

// H2ResponseWriter writes DATAGRAM capsules on the CONNECT-UDP response body.
// Fountain: relay UDP drain + Append* with byte threshold flush. ICMP/bidi Write: h2o 1:1 immediate.
type H2ResponseWriter struct {
	http.ResponseWriter
	mu                sync.Mutex
	pendingSinceFlush int
	pendingWire       bytes.Buffer
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
	if w.pendingWire.Cap() == 0 {
		w.pendingWire.Grow(H2DownlinkBulkFlushBytes)
	}
	if len(udpPayload) <= h2c.MaxUDPPayloadPerDatagramCapsule() {
		h2c.AppendDatagramCapsuleBuffer(&w.pendingWire, udpPayload)
	} else {
		h2c.AppendUDPPayloadAsDatagramCapsulesBuffer(&w.pendingWire, udpPayload)
	}
	w.pendingSinceFlush += h2c.UDPPayloadWireLen(udpPayload)
	return nil
}

func (w *H2ResponseWriter) writeCapsulesImmediateLocked(udpPayload []byte) error {
	w.pendingSinceFlush = 0
	w.pendingWire.Reset()
	if len(udpPayload) <= h2c.MaxUDPPayloadPerDatagramCapsule() {
		return h2c.WriteDatagramCapsule(w.ResponseWriter, udpPayload)
	}
	return h2c.WriteUDPPayloadAsDatagramCapsules(w.ResponseWriter, udpPayload)
}

func (w *H2ResponseWriter) flushLocked() error {
	if w.pendingWire.Len() > 0 {
		if _, err := h2c.WriteAll(w.ResponseWriter, w.pendingWire.Bytes()); err != nil {
			return err
		}
		w.pendingWire.Reset()
	}
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

func newH2DownlinkWriter(w http.ResponseWriter, _ LegProfile) *H2ResponseWriter {
	return &H2ResponseWriter{ResponseWriter: w}
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
	onward := &cudprelay.DirectH2OnwardUplink{Conn: conn}
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
		select {
		case <-downlinkReady:
		case <-relayCtx.Done():
			return
		}
		// h2o udp_on_read: 1 UDP datagram → 1 RFC9297 capsule → flush (no S2C batch).
		downErr = cudprelay.RelayH2ConnectDownlinkImmediate(relayCtx, conn, H2ServerUDPReadBuf, downlinkW)
	}()
	wg.Wait()
	joined := errors.Join(upErr, downErr)
	_ = http.NewResponseController(w).Flush()
	return joined
}
