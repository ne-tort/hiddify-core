package http3

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"net"
	"sync"
	"sync/atomic"
	"unsafe"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3/qlog"
	"github.com/quic-go/quic-go/qlogwriter"
	"github.com/quic-go/quic-go/quicvarint"
)

const maxQuarterStreamID = 1<<60 - 1

// ProxiedIPDatagramHeadroom is reserved before each outbound IP slice so InPlace
// enqueue can prepend RFC9297 (quarter-stream varint + context ID) without a copy.
// Must match connectip netstack/pump ProxiedIPDatagramHeadroom and
// connect-ip-go.ProxiedIPOutboundHeadroom (locked by TestP215HeadroomEquality).
const ProxiedIPDatagramHeadroom = 16

// invalidStreamID is a stream ID that is invalid. The first valid stream ID in QUIC is 0.
const invalidStreamID = quic.StreamID(-1)

var unknownStreamDatagramDropTotal atomic.Uint64

// UnknownStreamDatagramDropTotal returns process-wide count of DATAGRAM frames
// dropped because they referenced an unknown HTTP/3 stream mapping.
func UnknownStreamDatagramDropTotal() uint64 {
	return unknownStreamDatagramDropTotal.Load()
}

// Under high-rate CONNECT-UDP / CONNECT-IP startup bursts, DATAGRAMs can arrive
// before TrackStream() wiring completes. Keep a larger bounded backlog to avoid
// dropping a few initial packets and then stalling payload-integrity receivers.
const unknownStreamPendingQueuePerStream = 512
const unknownStreamPendingQueueGlobal = 65536

// rawConn is an HTTP/3 connection.
// It provides HTTP/3 specific functionality by wrapping a quic.Conn,
// in particular handling of unidirectional HTTP/3 streams, SETTINGS and datagrams.
type rawConn struct {
	conn *quic.Conn

	logger *slog.Logger

	enableDatagrams bool

	streamMx sync.RWMutex
	streams  map[quic.StreamID]*stateTrackingStream
	// pendingDatagrams buffers DATAGRAM payloads that arrived before TrackStream mapping.
	// This narrows setup-race loss for high-rate MASQUE traffic.
	pendingDatagrams map[quic.StreamID][][]byte
	pendingCount     int

	rcvdControlStr      atomic.Bool
	rcvdQPACKEncoderStr atomic.Bool
	rcvdQPACKDecoderStr atomic.Bool
	controlStrHandler   func(*quic.ReceiveStream, *frameParser) // is called *after* the SETTINGS frame was parsed

	onStreamsEmpty func()

	settings         *Settings
	receivedSettings chan struct{}

	qlogger   qlogwriter.Recorder
	qloggerWG sync.WaitGroup // tracks goroutines that may produce qlog events
}

func newRawConn(
	quicConn *quic.Conn,
	enableDatagrams bool,
	onStreamsEmpty func(),
	controlStrHandler func(*quic.ReceiveStream, *frameParser),
	qlogger qlogwriter.Recorder,
	logger *slog.Logger,
) *rawConn {
	c := &rawConn{
		conn:              quicConn,
		logger:            logger,
		enableDatagrams:   enableDatagrams,
		receivedSettings:  make(chan struct{}),
		streams:           make(map[quic.StreamID]*stateTrackingStream),
		pendingDatagrams:  make(map[quic.StreamID][][]byte),
		qlogger:           qlogger,
		onStreamsEmpty:    onStreamsEmpty,
		controlStrHandler: controlStrHandler,
	}
	if qlogger != nil {
		context.AfterFunc(quicConn.Context(), c.closeQlogger)
	}
	return c
}

func (c *rawConn) OpenUniStream() (*quic.SendStream, error) {
	return c.conn.OpenUniStream()
}

// openControlStream opens the control stream and sends the SETTINGS frame.
// It returns the control stream (needed by the server for sending GOAWAY later).
func (c *rawConn) openControlStream(settings *settingsFrame) (*quic.SendStream, error) {
	c.qloggerWG.Add(1)
	defer c.qloggerWG.Done()

	str, err := c.conn.OpenUniStream()
	if err != nil {
		return nil, err
	}
	b := make([]byte, 0, 64)
	b = quicvarint.Append(b, streamTypeControlStream)
	b = settings.Append(b)
	if c.qlogger != nil {
		sf := qlog.SettingsFrame{
			MaxFieldSectionSize: settings.MaxFieldSectionSize,
			Other:               maps.Clone(settings.Other),
		}
		if settings.Datagram {
			sf.Datagram = pointer(true)
		}
		if settings.ExtendedConnect {
			sf.ExtendedConnect = pointer(true)
		}
		c.qlogger.RecordEvent(qlog.FrameCreated{
			StreamID: str.StreamID(),
			Raw:      qlog.RawInfo{Length: len(b)},
			Frame:    qlog.Frame{Frame: sf},
		})
	}
	if _, err := str.Write(b); err != nil {
		return nil, err
	}
	return str, nil
}

func (c *rawConn) TrackStream(str *quic.Stream) *stateTrackingStream {
	hstr := newStateTrackingStream(str, c,
		func(b []byte) error { return c.sendDatagram(str.StreamID(), b) },
		func(b []byte) error { return c.sendDatagramNoWake(str.StreamID(), b) },
	)

	var pending [][]byte
	c.streamMx.Lock()
	c.streams[str.StreamID()] = hstr
	if queued, ok := c.pendingDatagrams[str.StreamID()]; ok {
		pending = queued
		c.pendingCount -= len(queued)
		delete(c.pendingDatagrams, str.StreamID())
	}
	c.qloggerWG.Add(1)
	c.streamMx.Unlock()
	for _, d := range pending {
		hstr.enqueueDatagram(d)
	}
	return hstr
}

func (c *rawConn) RemoteAddr() net.Addr {
	return c.conn.RemoteAddr()
}

func (c *rawConn) ConnectionState() quic.ConnectionState {
	return c.conn.ConnectionState()
}

func (c *rawConn) clearStream(id quic.StreamID) {
	c.streamMx.Lock()
	defer c.streamMx.Unlock()

	if _, ok := c.streams[id]; ok {
		delete(c.streams, id)
		c.qloggerWG.Done()
	}
	if pending, ok := c.pendingDatagrams[id]; ok {
		c.pendingCount -= len(pending)
		delete(c.pendingDatagrams, id)
	}
	if len(c.streams) == 0 {
		c.onStreamsEmpty()
	}
}

func (c *rawConn) evictOnePendingDatagramLocked() bool {
	for sid, q := range c.pendingDatagrams {
		if len(q) == 0 {
			delete(c.pendingDatagrams, sid)
			continue
		}
		if len(q) == 1 {
			delete(c.pendingDatagrams, sid)
		} else {
			c.pendingDatagrams[sid] = q[1:]
		}
		c.pendingCount--
		return true
	}
	return false
}

func (c *rawConn) enqueueUnknownStreamDatagram(streamID quic.StreamID, payload []byte) bool {
	c.streamMx.Lock()
	defer c.streamMx.Unlock()
	if _, known := c.streams[streamID]; known {
		return false
	}
	q := c.pendingDatagrams[streamID]
	if len(q) >= unknownStreamPendingQueuePerStream {
		// Keep recent datagrams for stream-setup race windows.
		q = q[1:]
		c.pendingCount--
		unknownStreamDatagramDropTotal.Add(1)
	}
	if c.pendingCount >= unknownStreamPendingQueueGlobal {
		if !c.evictOnePendingDatagramLocked() {
			return false
		}
		unknownStreamDatagramDropTotal.Add(1)
	}
	cp := append([]byte(nil), payload...)
	c.pendingDatagrams[streamID] = append(q, cp)
	c.pendingCount++
	return true
}

func (c *rawConn) hasActiveStreams() bool {
	c.streamMx.RLock()
	defer c.streamMx.RUnlock()

	return len(c.streams) > 0
}

func (c *rawConn) CloseWithError(code quic.ApplicationErrorCode, msg string) error {
	return c.conn.CloseWithError(code, msg)
}

func (c *rawConn) handleUnidirectionalStream(str *quic.ReceiveStream, isServer bool) {
	c.qloggerWG.Add(1)
	defer c.qloggerWG.Done()

	streamType, err := quicvarint.Read(quicvarint.NewReader(str))
	if err != nil {
		if c.logger != nil {
			c.logger.Debug("reading stream type on stream failed", "stream ID", str.StreamID(), "error", err)
		}
		return
	}
	// We're only interested in the control stream here.
	switch streamType {
	case streamTypeControlStream:
	case streamTypeQPACKEncoderStream:
		if isFirst := c.rcvdQPACKEncoderStr.CompareAndSwap(false, true); !isFirst {
			c.CloseWithError(quic.ApplicationErrorCode(ErrCodeStreamCreationError), "duplicate QPACK encoder stream")
		}
		// Our QPACK implementation doesn't use the dynamic table yet.
		return
	case streamTypeQPACKDecoderStream:
		if isFirst := c.rcvdQPACKDecoderStr.CompareAndSwap(false, true); !isFirst {
			c.CloseWithError(quic.ApplicationErrorCode(ErrCodeStreamCreationError), "duplicate QPACK decoder stream")
		}
		// Our QPACK implementation doesn't use the dynamic table yet.
		return
	case streamTypePushStream:
		if isServer {
			// only the server can push
			c.CloseWithError(quic.ApplicationErrorCode(ErrCodeStreamCreationError), "")
		} else {
			// we never increased the Push ID, so we don't expect any push streams
			c.CloseWithError(quic.ApplicationErrorCode(ErrCodeIDError), "")
		}
		return
	default:
		str.CancelRead(quic.StreamErrorCode(ErrCodeStreamCreationError))
		return
	}
	// Only a single control stream is allowed.
	if isFirstControlStr := c.rcvdControlStr.CompareAndSwap(false, true); !isFirstControlStr {
		c.conn.CloseWithError(quic.ApplicationErrorCode(ErrCodeStreamCreationError), "duplicate control stream")
		return
	}
	c.handleControlStream(str)
}

func (c *rawConn) handleControlStream(str *quic.ReceiveStream) {
	fp := &frameParser{closeConn: c.conn.CloseWithError, r: str, streamID: str.StreamID()}
	f, err := fp.ParseNext(c.qlogger)
	if err != nil {
		var serr *quic.StreamError
		if err == io.EOF || errors.As(err, &serr) {
			c.conn.CloseWithError(quic.ApplicationErrorCode(ErrCodeClosedCriticalStream), "")
			return
		}
		c.conn.CloseWithError(quic.ApplicationErrorCode(ErrCodeFrameError), "")
		return
	}
	sf, ok := f.(*settingsFrame)
	if !ok {
		c.conn.CloseWithError(quic.ApplicationErrorCode(ErrCodeMissingSettings), "")
		return
	}
	c.settings = &Settings{
		EnableDatagrams:       sf.Datagram,
		EnableExtendedConnect: sf.ExtendedConnect,
		Other:                 sf.Other,
	}
	close(c.receivedSettings)
	if sf.Datagram {
		// If datagram support was enabled on our side as well as on the server side,
		// we can expect it to have been negotiated both on the transport and on the HTTP/3 layer.
		// Note: ConnectionState() will block until the handshake is complete (relevant when using 0-RTT).
		if c.enableDatagrams && !c.ConnectionState().SupportsDatagrams.Remote {
			c.CloseWithError(quic.ApplicationErrorCode(ErrCodeSettingsError), "missing QUIC Datagram support")
			return
		}
		c.qloggerWG.Add(1)
		go func() {
			defer c.qloggerWG.Done()
			if err := c.receiveDatagrams(); err != nil {
				if c.logger != nil {
					c.logger.Debug("receiving datagrams failed", "error", err)
				}
			}
		}()
	}

	if c.controlStrHandler != nil {
		c.controlStrHandler(str, fp)
	}
}

func (c *rawConn) sendDatagram(streamID quic.StreamID, b []byte) error {
	return c.sendDatagramMaybeWake(streamID, b, true)
}

func (c *rawConn) sendDatagramNoWake(streamID quic.StreamID, b []byte) error {
	return c.sendDatagramMaybeWake(streamID, b, false)
}

// enqueueOutgoingDatagramFrameNoWake queues a fully formatted HTTP/3 DATAGRAM frame
// (quarter-stream-id varint + payload). release runs after payload is copied into outgoing frames.
func (c *rawConn) enqueueOutgoingDatagramFrameNoWake(data []byte, release func()) error {
	if c == nil || c.conn == nil {
		if release != nil {
			release()
		}
		return errors.New("http3: nil conn")
	}
	if c.qlogger != nil {
		quarterStreamID, n, err := quicvarint.Parse(data)
		if err == nil {
			c.qlogger.RecordEvent(qlog.DatagramCreated{
				QuaterStreamID: quarterStreamID,
				Raw: qlog.RawInfo{
					Length:        len(data),
					PayloadLength: len(data) - n,
				},
			})
		}
	}
	return c.conn.EnqueueOutgoingDatagramWithRelease(data, release)
}

func (c *rawConn) sendDatagramMaybeWake(streamID quic.StreamID, b []byte, wake bool) error {
	quarterStreamID := uint64(streamID / 4)
	bufPtr := quic.AcquireHTTP3DatagramBuffer()
	*bufPtr = (*bufPtr)[:0]
	*bufPtr = quicvarint.Append(*bufPtr, quarterStreamID)
	*bufPtr = append(*bufPtr, b...)
	return c.enqueuePooledHTTPDatagramMaybeWake(quarterStreamID, len(b), bufPtr, wake)
}

// sendProxiedIPDatagram enqueues RFC9297 proxied IP with one copy into the QUIC DATAGRAM buffer.
func (c *rawConn) sendProxiedIPDatagram(streamID quic.StreamID, contextPrefix, ipPacket []byte) error {
	return c.sendProxiedIPDatagramMaybeWake(streamID, contextPrefix, ipPacket, true)
}

// sendProxiedIPDatagramNoWake enqueues proxied IP without scheduling QUIC send work.
func (c *rawConn) sendProxiedIPDatagramNoWake(streamID quic.StreamID, contextPrefix, ipPacket []byte) error {
	return c.sendProxiedIPDatagramMaybeWake(streamID, contextPrefix, ipPacket, false)
}

func (c *rawConn) sendProxiedIPDatagramMaybeWake(streamID quic.StreamID, contextPrefix, ipPacket []byte, wake bool) error {
	quarterStreamID := uint64(streamID / 4)
	varintLen := quicvarint.Len(quarterStreamID)
	total := varintLen + len(contextPrefix) + len(ipPacket)
	bufPtr := quic.AcquireHTTP3DatagramBuffer()
	if cap(*bufPtr) < total {
		*bufPtr = make([]byte, 0, total)
	}
	*bufPtr = (*bufPtr)[:0]
	*bufPtr = quicvarint.Append(*bufPtr, quarterStreamID)
	*bufPtr = append(*bufPtr, contextPrefix...)
	*bufPtr = append(*bufPtr, ipPacket...)
	return c.enqueuePooledHTTPDatagramMaybeWake(quarterStreamID, len(contextPrefix)+len(ipPacket), bufPtr, wake)
}

func proxiedIPFrameFromPool(ipPacket []byte, prefixLen int) (frame []byte, ok bool) {
	if prefixLen <= 0 || prefixLen > ProxiedIPDatagramHeadroom || len(ipPacket) == 0 {
		return nil, false
	}
	if cap(ipPacket) < len(ipPacket)+ProxiedIPDatagramHeadroom {
		return nil, false
	}
	ipStart := uintptr(unsafe.Pointer(unsafe.SliceData(ipPacket)))
	basePtr := unsafe.Pointer(ipStart - uintptr(ProxiedIPDatagramHeadroom))
	fullCap := cap(ipPacket) + ProxiedIPDatagramHeadroom
	full := unsafe.Slice((*byte)(basePtr), fullCap)
	prefixStart := ProxiedIPDatagramHeadroom - prefixLen
	end := ProxiedIPDatagramHeadroom + len(ipPacket)
	if end > fullCap {
		return nil, false
	}
	return full[prefixStart:end], true
}

func (c *rawConn) sendProxiedIPDatagramInPlaceNoWake(streamID quic.StreamID, contextPrefix, ipPacket []byte, release func()) error {
	return c.sendProxiedIPDatagramInPlaceMaybeWake(streamID, contextPrefix, ipPacket, release, false)
}

func (c *rawConn) sendProxiedIPDatagramInPlaceMaybeWake(streamID quic.StreamID, contextPrefix, ipPacket []byte, release func(), wake bool) error {
	quarterStreamID := uint64(streamID / 4)
	varintLen := quicvarint.Len(quarterStreamID)
	prefixLen := varintLen + len(contextPrefix)
	if prefixLen > ProxiedIPDatagramHeadroom {
		err := c.sendProxiedIPDatagramMaybeWake(streamID, contextPrefix, ipPacket, wake)
		if release != nil {
			release()
		}
		return err
	}
	frame, ok := proxiedIPFrameFromPool(ipPacket, prefixLen)
	if !ok {
		err := c.sendProxiedIPDatagramMaybeWake(streamID, contextPrefix, ipPacket, wake)
		if release != nil {
			release()
		}
		return err
	}
	buf := quicvarint.Append(frame[:0], quarterStreamID)
	if len(buf) != varintLen {
		if release != nil {
			release()
		}
		return fmt.Errorf("http3: proxied IP varint length mismatch")
	}
	copy(frame[varintLen:prefixLen], contextPrefix)
	err := c.conn.EnqueueOutgoingDatagramWithRelease(frame, release)
	if err != nil {
		return err
	}
	if wake {
		quic.MasqueWakeConnSend(c.conn)
	}
	return nil
}

func (c *rawConn) flushDatagramSendWake() {
	if c == nil || c.conn == nil {
		return
	}
	quic.MasqueWakeConnSendDatagramCoalesced(c.conn)
}

// DatagramSendBacklog returns queued outgoing QUIC DATAGRAM frames on this connection.
func (c *rawConn) DatagramSendBacklog() int {
	if c == nil || c.conn == nil {
		return 0
	}
	return c.conn.DatagramSendBacklog()
}

func (c *rawConn) flushDatagramReceiveWake() {
	c.flushDatagramSendWake()
}

func (c *rawConn) enqueuePooledHTTPDatagram(quarterStreamID uint64, payloadLen int, bufPtr *[]byte) error {
	return c.enqueuePooledHTTPDatagramMaybeWake(quarterStreamID, payloadLen, bufPtr, true)
}

func (c *rawConn) enqueuePooledHTTPDatagramMaybeWake(quarterStreamID uint64, payloadLen int, bufPtr *[]byte, wake bool) error {
	if c.qlogger != nil {
		c.qlogger.RecordEvent(qlog.DatagramCreated{
			QuaterStreamID: quarterStreamID,
			Raw: qlog.RawInfo{
				Length:        len(*bufPtr),
				PayloadLength: payloadLen,
			},
		})
	}
	if err := c.conn.EnqueuePooledHTTPDatagram(bufPtr); err != nil {
		quic.ReleaseHTTP3DatagramBuffer(bufPtr)
		return err
	}
	if wake {
		quic.MasqueWakeConnSend(c.conn)
	}
	return nil
}

func (c *rawConn) receiveDatagramDispatch(b []byte) error {
	quarterStreamID, n, err := quicvarint.Parse(b)
	if err != nil {
		quic.ReleaseMasqueDatagramReceiveBuffer(b)
		c.CloseWithError(quic.ApplicationErrorCode(ErrCodeDatagramError), "")
		return fmt.Errorf("could not read quarter stream id: %w", err)
	}
	if c.qlogger != nil {
		c.qlogger.RecordEvent(qlog.DatagramParsed{
			QuaterStreamID: quarterStreamID,
			Raw: qlog.RawInfo{
				Length:        len(b),
				PayloadLength: len(b) - n,
			},
		})
	}
	if quarterStreamID > maxQuarterStreamID {
		quic.ReleaseMasqueDatagramReceiveBuffer(b)
		c.CloseWithError(quic.ApplicationErrorCode(ErrCodeDatagramError), "")
		return fmt.Errorf("invalid quarter stream id: %d", quarterStreamID)
	}
	payloadLen := len(b) - n
	if n > 0 {
		copy(b, b[n:])
	}
	b = b[:payloadLen]
	streamID := quic.StreamID(4 * quarterStreamID)
	c.streamMx.RLock()
	dg, ok := c.streams[streamID]
	c.streamMx.RUnlock()
	if !ok {
		if !c.enqueueUnknownStreamDatagram(streamID, b) {
			unknownStreamDatagramDropTotal.Add(1)
		}
		quic.ReleaseMasqueDatagramReceiveBuffer(b)
		return nil
	}
	if !dg.enqueueDatagramOwned(b) {
		quic.ReleaseMasqueDatagramReceiveBuffer(b)
	}
	return nil
}

func (c *rawConn) receiveDatagrams() error {
	for {
		b, err := c.conn.ReceiveDatagram(context.Background())
		if err != nil {
			return err
		}
		if err := c.receiveDatagramDispatch(b); err != nil {
			return err
		}
		// QUIC rcv buffers may already hold multiple frames; draining here cuts
		// scheduling overhead between HTTP/3 routing and CONNECT-UDP/CONNECT-IP hot path.
		for {
			b2, ok := c.conn.TryReceiveDatagram()
			if !ok {
				break
			}
			if err := c.receiveDatagramDispatch(b2); err != nil {
				return err
			}
		}
		c.flushDatagramReceiveWake()
	}
}

// ReceivedSettings returns a channel that is closed once the peer's SETTINGS frame was received.
// Settings can be optained from the Settings method after the channel was closed.
func (c *rawConn) ReceivedSettings() <-chan struct{} { return c.receivedSettings }

// Settings returns the settings received on this connection.
// It is only valid to call this function after the channel returned by ReceivedSettings was closed.
func (c *rawConn) Settings() *Settings { return c.settings }

// closeQlogger waits for all goroutines that may produce qlog events to finish,
// then closes the qlogger.
func (c *rawConn) closeQlogger() {
	if c.qlogger == nil {
		return
	}
	c.qloggerWG.Wait()
	c.qlogger.Close()
}
