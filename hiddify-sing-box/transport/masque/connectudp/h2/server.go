package h2

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/http"
	"sync"

	"github.com/sagernet/sing-box/transport/masque/connectudp/frame"
	cudprelay "github.com/sagernet/sing-box/transport/masque/connectudp/relay"
	h2c "github.com/sagernet/sing-box/transport/masque/h2"
)

const (
	H2ServerUDPReadBuf    = 65535
	H2ResponseBodyBufSize = 256 * 1024
	// H2DownlinkPendingGrow is the initial pendingWire capacity (aligned with relay
	// h2DownlinkBatchWire). Flush policy is per-RX-batch FlushPending only (AUDIT B7 / F2.5)
	// — Append does not auto-flush at a byte threshold.
	H2DownlinkPendingGrow = 64 * 1024
)

// H2DownlinkBulkFlushBytes is retained as an alias for Grow / tests (not an Append auto-flush threshold).
const H2DownlinkBulkFlushBytes = H2DownlinkPendingGrow

// H2ResponseWriter writes DATAGRAM capsules on the CONNECT-UDP response body.
// Fountain: Append buffers; relay calls FlushPending after each UDP RX batch.
// ICMP/bidi Write: h2o 1:1 immediate (drains any pending first — A4).
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

// AppendUDPPayloadAsCapsules appends RFC9297 wire only. Caller (fountain relay) must
// FlushPending after each onward UDP batch — no byte-threshold auto-flush (B7).
func (w *H2ResponseWriter) AppendUDPPayloadAsCapsules(udpPayload []byte) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if len(udpPayload) == 0 {
		return w.writeCapsulesImmediateLocked(nil)
	}
	return w.appendCapsulesLocked(udpPayload)
}

func (w *H2ResponseWriter) appendCapsulesLocked(udpPayload []byte) error {
	if err := frame.CheckConnectUDPUDPPayload(len(udpPayload), h2c.MaxUDPPayloadPerDatagramCapsule()); err != nil {
		return err
	}
	if w.pendingWire.Cap() == 0 {
		w.pendingWire.Grow(H2DownlinkPendingGrow)
	}
	h2c.AppendDatagramCapsuleBuffer(&w.pendingWire, udpPayload)
	w.pendingSinceFlush += h2c.UDPPayloadWireLen(udpPayload)
	return nil
}

func (w *H2ResponseWriter) writeCapsulesImmediateLocked(udpPayload []byte) error {
	// Drain fountain pending first — do not Reset/drop accumulated S2C (AUDIT A4 / F2.2).
	// Avoid flushLocked(): it always FlushResponse even when pending empty (breaks h2o flush counts).
	if w.pendingWire.Len() > 0 {
		if _, err := h2c.WriteAll(w.ResponseWriter, w.pendingWire.Bytes()); err != nil {
			return err
		}
		w.pendingWire.Reset()
		w.pendingSinceFlush = 0
	}
	if err := frame.CheckConnectUDPUDPPayload(len(udpPayload), h2c.MaxUDPPayloadPerDatagramCapsule()); err != nil {
		return err
	}
	return h2c.WriteDatagramCapsule(w.ResponseWriter, udpPayload)
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
	defer cudprelay.BeginRelaySessionStats("h2-bidi")()
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
