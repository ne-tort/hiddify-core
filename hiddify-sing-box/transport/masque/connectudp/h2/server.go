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
	// H2DownlinkPendingGrow is the initial pendingWire capacity.
	H2DownlinkPendingGrow = 64 * 1024
)

// H2DownlinkBulkFlushBytes is retained as an alias for Grow / tests (not an Append auto-flush threshold).
const H2DownlinkBulkFlushBytes = H2DownlinkPendingGrow

// H2ResponseWriter writes DATAGRAM capsules on the CONNECT-UDP response body.
// Bidi (approach A): immediate Write per UDP datagram. Append/FlushPending remain for tests
// that exercise fountain buffering; flush never holds mu across blocking http2 Write.
type H2ResponseWriter struct {
	http.ResponseWriter
	mu                sync.Mutex
	pendingSinceFlush int
	pendingWire       bytes.Buffer
}

func (w *H2ResponseWriter) WriteUDPPayloadAsCapsules(udpPayload []byte) error {
	if err := frame.CheckConnectUDPUDPPayload(len(udpPayload), h2c.MaxUDPPayloadPerDatagramCapsule()); err != nil {
		return err
	}
	w.mu.Lock()
	drain := w.takePendingLocked()
	w.mu.Unlock()
	if len(drain) > 0 {
		if _, err := h2c.WriteAll(w.ResponseWriter, drain); err != nil {
			return err
		}
	}
	return h2c.WriteDatagramCapsule(w.ResponseWriter, udpPayload)
}

// AppendUDPPayloadAsCapsules appends RFC9297 wire only. Caller must FlushPending after a batch.
func (w *H2ResponseWriter) AppendUDPPayloadAsCapsules(udpPayload []byte) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if len(udpPayload) == 0 {
		return nil
	}
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

func (w *H2ResponseWriter) takePendingLocked() []byte {
	if w.pendingWire.Len() == 0 {
		return nil
	}
	pending := w.pendingWire
	w.pendingWire = bytes.Buffer{}
	w.pendingSinceFlush = 0
	return pending.Bytes()
}

func (w *H2ResponseWriter) FlushPending() error {
	w.mu.Lock()
	if w.pendingSinceFlush <= 0 {
		w.mu.Unlock()
		return nil
	}
	wire := w.takePendingLocked()
	w.mu.Unlock()
	if len(wire) > 0 {
		if _, err := h2c.WriteAll(w.ResponseWriter, wire); err != nil {
			return err
		}
	}
	h2c.FlushResponse(w.ResponseWriter)
	return nil
}

func NewDownlinkResponseWriter(w http.ResponseWriter) *H2ResponseWriter {
	return &H2ResponseWriter{ResponseWriter: w}
}

// ServeH2 relays UDP over HTTP/2 CONNECT-UDP (h2o event-loop semantics: 2 goroutines).
func ServeH2(w http.ResponseWriter, r *http.Request, conn *net.UDPConn) error {
	if w == nil || r == nil || conn == nil {
		return errors.New("masque h2: connect-udp relay: nil argument")
	}
	defer cudprelay.BeginRelaySessionStats("h2-bidi")()
	downlinkW := NewDownlinkResponseWriter(w)
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
		// Only uplink closes request Body: downlink exit must not tear Body while
		// uplink still peels already-ACKed DATA (Close/cancel race → pre_server loss).
		defer shutdownRelay()
		defer closeUDPConn()
		defer cancelRelay()
		upErr = cudprelay.RelayH2ConnectUplink(r, onward, H2ResponseBodyBufSize, signalDownlinkReady, onICMP)
	}()
	go func() {
		defer wg.Done()
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
