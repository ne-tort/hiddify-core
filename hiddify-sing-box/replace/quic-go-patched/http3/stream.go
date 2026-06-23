package http3

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptrace"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3/qlog"
	"github.com/quic-go/quic-go/qlogwriter"

	"github.com/quic-go/qpack"
)

type datagramStream interface {
	io.ReadWriteCloser
	CancelRead(quic.StreamErrorCode)
	CancelWrite(quic.StreamErrorCode)
	StreamID() quic.StreamID
	Context() context.Context
	SetDeadline(time.Time) error
	SetReadDeadline(time.Time) error
	SetWriteDeadline(time.Time) error
	SendDatagram(b []byte) error
	ReceiveDatagram(ctx context.Context) ([]byte, error)

	QUICStream() *quic.Stream
}

// A Stream is an HTTP/3 stream.
//
// When writing to and reading from the stream, data is framed in HTTP/3 DATA frames.
type Stream struct {
	datagramStream
	conn        *rawConn
	frameParser *frameParser

	buf []byte // used as a temporary buffer when writing the HTTP/3 frame headers

	bytesRemainingInFrame uint64

	qlogger qlogwriter.Recorder

	parseTrailer  func(io.Reader, *headersFrame) error
	parsedTrailer bool

	masqueCoalesceBuf []byte // batched CONNECT DATA frames (h2o/Invisv bulk coalesce)

	masqueTunnelData bool // CONNECT tunnel bulk DATA phase (fast frame parse)
}

func newStream(
	str datagramStream,
	conn *rawConn,
	trace *httptrace.ClientTrace,
	parseTrailer func(io.Reader, *headersFrame) error,
	qlogger qlogwriter.Recorder,
) *Stream {
	return &Stream{
		datagramStream: str,
		conn:           conn,
		buf:            make([]byte, 16),
		qlogger:        qlogger,
		parseTrailer:   parseTrailer,
		frameParser: &frameParser{
			r:         &tracingReader{Reader: str, trace: trace},
			streamID:  str.StreamID(),
			closeConn: conn.CloseWithError,
		},
	}
}

func (s *Stream) Read(b []byte) (int, error) {
	if s.bytesRemainingInFrame == 0 {
	parseLoop:
		for {
			var frame frame
			var err error
			if s.masqueTunnelData && !s.parsedTrailer {
				frame, err = s.frameParser.parseTunnelDataFrame(s.qlogger)
			} else {
				frame, err = s.frameParser.ParseNext(s.qlogger)
			}
			if err != nil {
				return 0, err
			}
			switch f := frame.(type) {
			case *dataFrame:
				if s.parsedTrailer {
					return 0, errors.New("DATA frame received after trailers")
				}
				s.bytesRemainingInFrame = f.Length
				break parseLoop
			case *headersFrame:
				if s.parsedTrailer {
					maybeQlogInvalidHeadersFrame(s.qlogger, s.StreamID(), f.Length)
					return 0, errors.New("additional HEADERS frame received after trailers")
				}
				s.parsedTrailer = true
				return 0, s.parseTrailer(s.datagramStream, f)
			default:
				s.conn.CloseWithError(quic.ApplicationErrorCode(ErrCodeFrameUnexpected), "")
				// parseNextFrame skips over unknown frame types
				// Therefore, this condition is only entered when we parsed another known frame type.
				return 0, fmt.Errorf("peer sent an unexpected frame: %T", f)
			}
		}
	}

	var n int
	var err error
	if s.bytesRemainingInFrame < uint64(len(b)) {
		n, err = s.datagramStream.Read(b[:s.bytesRemainingInFrame])
	} else {
		n, err = s.datagramStream.Read(b)
	}
	s.bytesRemainingInFrame -= uint64(n)
	if n > 0 {
		masqueWakeSendAfterReceiveRead(s, n)
	}
	return n, err
}

func masqueStreamDuplexUploadWake(s *Stream) bool {
	if s == nil || s.datagramStream == nil {
		return false
	}
	qs := s.datagramStream.QUICStream()
	return qs != nil && quic.MasqueIsBidiDuplexUploadStarted(qs)
}

const masqueHTTP3WriteToBufLen = 256 * 1024

func masqueStreamDownloadPrimaryReceive(s *Stream) bool {
	if s == nil || s.datagramStream == nil {
		return false
	}
	qs := s.datagramStream.QUICStream()
	return qs != nil && quic.MasqueIsBidiDownloadReceiveOnly(qs) && !quic.MasqueIsBidiDuplexUploadStarted(qs)
}

// WriteTo drains tunneled CONNECT payload. Batched wake every 256 KiB delivered (64 KiB during duplex / download-primary).
func (s *Stream) WriteTo(w io.Writer) (int64, error) {
	wakeBatch := masqueHTTP3WriteToBufLen
	readCap := masqueHTTP3WriteToBufLen
	if masqueStreamDuplexUploadWake(s) {
		wakeBatch = 64 * 1024
		if qs := s.datagramStream.QUICStream(); qs != nil && quic.MasqueUploadSendStarved(qs) {
			readCap = 16 * 1024
		}
	} else if masqueStreamDownloadPrimaryReceive(s) {
		wakeBatch = 4 * 1024
		readCap = masqueHTTP3WriteToBufLen
	}
	buf := make([]byte, readCap)
	var total int64
	var deliveryPending int
	flushDeliveryWake := func(delivered int) {
		if delivered <= 0 {
			return
		}
		deliveryPending += delivered
		if deliveryPending >= wakeBatch {
			deliveryPending = 0
			masqueWakeSendAfterReceiveRead(s, delivered)
		}
	}
	for {
		nr, err := s.Read(buf)
		if nr > 0 {
			nw, werr := w.Write(buf[:nr])
			total += int64(nw)
			if nw > 0 {
				flushDeliveryWake(nw)
			}
			if werr != nil {
				if deliveryPending > 0 {
					pending := deliveryPending
					deliveryPending = 0
					masqueWakeSendAfterReceiveRead(s, pending)
				}
				return total, werr
			}
			if nw < nr {
				return total, io.ErrShortWrite
			}
		}
		if err != nil {
			if err == io.EOF {
				if deliveryPending > 0 {
					pending := deliveryPending
					deliveryPending = 0
					masqueWakeSendAfterReceiveRead(s, pending)
				}
				return total, nil
			}
			return total, err
		}
	}
}

func (s *Stream) hasMoreData() bool {
	return s.bytesRemainingInFrame > 0
}

func (s *Stream) writeDataFramePayload(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}
	s.buf = s.buf[:0]
	s.buf = (&dataFrame{Length: uint64(len(b))}).Append(s.buf)
	if s.qlogger != nil {
		s.qlogger.RecordEvent(qlog.FrameCreated{
			StreamID: s.StreamID(),
			Raw: qlog.RawInfo{
				Length:        len(s.buf) + len(b),
				PayloadLength: len(b),
			},
			Frame: qlog.Frame{Frame: qlog.DataFrame{}},
		})
	}
	if _, err := s.datagramStream.Write(s.buf); err != nil {
		return 0, err
	}
	n, err := s.datagramStream.Write(b)
	if n > 0 {
		masqueWakeSendAfterUploadWrite(s, n)
	}
	return n, err
}

func (s *Stream) flushMasqueWriteCoalesce() error {
	if s == nil || len(s.masqueCoalesceBuf) == 0 {
		return nil
	}
	payload := s.masqueCoalesceBuf
	s.masqueCoalesceBuf = s.masqueCoalesceBuf[:0]
	_, err := s.writeDataFramePayload(payload)
	return err
}

// Write queues tunneled CONNECT payload. Bulk uploads coalesce into 256 KiB DATA frames (h2o/Invisv).
func (s *Stream) Write(b []byte) (int, error) {
	coalesceLen := masqueHTTP3WriteToBufLen
	total := len(b)
	for len(b) > 0 {
		if cap(s.masqueCoalesceBuf) == 0 {
			s.masqueCoalesceBuf = make([]byte, 0, coalesceLen)
		}
		space := coalesceLen - len(s.masqueCoalesceBuf)
		if space == 0 {
			if err := s.flushMasqueWriteCoalesce(); err != nil {
				return total - len(b), err
			}
			space = coalesceLen
		}
		n := len(b)
		if n > space {
			n = space
		}
		s.masqueCoalesceBuf = append(s.masqueCoalesceBuf, b[:n]...)
		b = b[n:]
		if len(s.masqueCoalesceBuf) >= coalesceLen {
			if err := s.flushMasqueWriteCoalesce(); err != nil {
				return total - len(b), err
			}
		}
	}
	return total, nil
}

// Close flushes pending coalesced DATA before closing the send half.
func (s *Stream) Close() error {
	if err := s.flushMasqueWriteCoalesce(); err != nil {
		return err
	}
	return s.datagramStream.Close()
}

func (s *Stream) writeUnframed(b []byte) (int, error) {
	n, err := s.datagramStream.Write(b)
	if n > 0 {
		masqueWakeSendAfterUploadWrite(s, n)
	}
	return n, err
}

func (s *Stream) StreamID() quic.StreamID {
	return s.datagramStream.StreamID()
}

func (s *Stream) SendDatagram(b []byte) error {
	// TODO: reject if datagrams are not negotiated (yet)
	return s.datagramStream.SendDatagram(b)
}

// SendDatagramNoWake enqueues CONNECT-UDP HTTP datagram without per-packet QUIC send wake.
func (s *Stream) SendDatagramNoWake(b []byte) error {
	if s == nil || s.datagramStream == nil {
		return errors.New("http3: nil stream")
	}
	if nw, ok := s.datagramStream.(interface{ SendDatagramNoWake([]byte) error }); ok {
		return nw.SendDatagramNoWake(b)
	}
	return s.datagramStream.SendDatagram(b)
}

// SendDatagramFrameNoWake enqueues a fully formatted HTTP/3 DATAGRAM frame without per-packet wake.
func (s *Stream) SendDatagramFrameNoWake(data []byte, release func()) error {
	if s == nil || s.conn == nil {
		if release != nil {
			release()
		}
		return errors.New("http3: nil stream")
	}
	return s.conn.enqueueOutgoingDatagramFrameNoWake(data, release)
}

// SendProxiedIPDatagram queues CONNECT-IP egress (context prefix + IP) with one pooled-buffer copy.
func (s *Stream) SendProxiedIPDatagram(contextPrefix, ipPacket []byte) error {
	if s == nil || s.conn == nil {
		return errors.New("http3: nil stream")
	}
	return s.conn.sendProxiedIPDatagram(s.StreamID(), contextPrefix, ipPacket)
}

// SendProxiedIPDatagramNoWake enqueues proxied IP without per-datagram QUIC send wake.
func (s *Stream) SendProxiedIPDatagramNoWake(contextPrefix, ipPacket []byte) error {
	if s == nil || s.conn == nil {
		return errors.New("http3: nil stream")
	}
	return s.conn.sendProxiedIPDatagramNoWake(s.StreamID(), contextPrefix, ipPacket)
}

// SendProxiedIPDatagramInPlaceNoWake enqueues from a caller-owned IP buffer with pool headroom.
func (s *Stream) SendProxiedIPDatagramInPlaceNoWake(contextPrefix, ipPacket []byte, release func()) error {
	if s == nil || s.conn == nil {
		if release != nil {
			release()
		}
		return errors.New("http3: nil stream")
	}
	return s.conn.sendProxiedIPDatagramInPlaceNoWake(s.StreamID(), contextPrefix, ipPacket, release)
}

// FlushProxiedIPDatagramSend schedules one QUIC send after a batched proxied-IP enqueue.
func (s *Stream) FlushProxiedIPDatagramSend() {
	if s == nil || s.conn == nil {
		return
	}
	s.conn.flushDatagramSendWake()
}

// DatagramSendBacklog returns queued outgoing QUIC DATAGRAM frames on the HTTP/3 connection.
func (s *Stream) DatagramSendBacklog() int {
	if s == nil || s.conn == nil {
		return 0
	}
	return s.conn.DatagramSendBacklog()
}

func (s *Stream) ReceiveDatagram(ctx context.Context) ([]byte, error) {
	// TODO: reject if datagrams are not negotiated (yet)
	return s.datagramStream.ReceiveDatagram(ctx)
}

// TryReceiveDatagram exposes a non-blocking datagram dequeue when the underlying stream supports it.
func (s *Stream) TryReceiveDatagram() ([]byte, bool) {
	type tryStream interface {
		TryReceiveDatagram() ([]byte, bool)
	}
	if ts, ok := s.datagramStream.(tryStream); ok {
		return ts.TryReceiveDatagram()
	}
	return nil, false
}

// A RequestStream is a low-level abstraction representing an HTTP/3 request stream.
// It decouples sending of the HTTP request from reading the HTTP response, allowing
// the application to optimistically use the stream (and, for example, send datagrams)
// before receiving the response.
//
// This is only needed for advanced use case, e.g. WebTransport and the various
// MASQUE proxying protocols.
type RequestStream struct {
	str *Stream

	responseBody io.ReadCloser // set by ReadResponse

	decoder            *qpack.Decoder
	requestWriter      *requestWriter
	maxHeaderBytes     int
	reqDone            chan<- struct{}
	disableCompression bool
	response           *http.Response

	sentRequest   bool
	requestedGzip bool
	isConnect     bool
}

func newRequestStream(
	str *Stream,
	requestWriter *requestWriter,
	reqDone chan<- struct{},
	decoder *qpack.Decoder,
	disableCompression bool,
	maxHeaderBytes int,
	rsp *http.Response,
) *RequestStream {
	return &RequestStream{
		str:                str,
		requestWriter:      requestWriter,
		reqDone:            reqDone,
		decoder:            decoder,
		disableCompression: disableCompression,
		maxHeaderBytes:     maxHeaderBytes,
		response:           rsp,
	}
}

// Read reads data from the underlying stream.
//
// It can only be used after the request has been sent (using SendRequestHeader)
// and the response has been consumed (using ReadResponse).
func (s *RequestStream) Read(b []byte) (int, error) {
	if s.responseBody == nil {
		return 0, errors.New("http3: invalid use of RequestStream.Read before ReadResponse")
	}
	return s.responseBody.Read(b)
}

// StreamID returns the QUIC stream ID of the underlying QUIC stream.
func (s *RequestStream) StreamID() quic.StreamID {
	return s.str.StreamID()
}

// Write writes data to the stream.
//
// It can only be used after the request has been sent (using SendRequestHeader).
func (s *RequestStream) Write(b []byte) (int, error) {
	if !s.sentRequest {
		return 0, errors.New("http3: invalid use of RequestStream.Write before SendRequestHeader")
	}
	return s.str.Write(b)
}

// Close closes the send-direction of the stream.
// It does not close the receive-direction of the stream.
func (s *RequestStream) Close() error {
	return s.str.Close()
}

// CancelRead aborts receiving on this stream.
// See [quic.Stream.CancelRead] for more details.
func (s *RequestStream) CancelRead(errorCode quic.StreamErrorCode) {
	s.str.CancelRead(errorCode)
}

// CancelWrite aborts sending on this stream.
// See [quic.Stream.CancelWrite] for more details.
func (s *RequestStream) CancelWrite(errorCode quic.StreamErrorCode) {
	s.str.CancelWrite(errorCode)
}

// Context returns a context derived from the underlying QUIC stream's context.
// See [quic.Stream.Context] for more details.
func (s *RequestStream) Context() context.Context {
	return s.str.Context()
}

// SetReadDeadline sets the deadline for Read calls.
func (s *RequestStream) SetReadDeadline(t time.Time) error {
	return s.str.SetReadDeadline(t)
}

// SetWriteDeadline sets the deadline for Write calls.
func (s *RequestStream) SetWriteDeadline(t time.Time) error {
	return s.str.SetWriteDeadline(t)
}

// SetDeadline sets the read and write deadlines associated with the stream.
// It is equivalent to calling both SetReadDeadline and SetWriteDeadline.
func (s *RequestStream) SetDeadline(t time.Time) error {
	return s.str.SetDeadline(t)
}

// SendDatagrams send a new HTTP Datagram (RFC 9297).
//
// It is only possible to send datagrams if the server enabled support for this extension.
// It is recommended (though not required) to send the request before calling this method,
// as the server might drop datagrams which it can't associate with an existing request.
func (s *RequestStream) SendDatagram(b []byte) error {
	return s.str.SendDatagram(b)
}

// SendDatagramNoWake enqueues an HTTP Datagram without per-packet QUIC send wake.
func (s *RequestStream) SendDatagramNoWake(b []byte) error {
	return s.str.SendDatagramNoWake(b)
}

// SendProxiedIPDatagram queues CONNECT-IP egress with one pooled-buffer copy.
func (s *RequestStream) SendProxiedIPDatagram(contextPrefix, ipPacket []byte) error {
	return s.str.SendProxiedIPDatagram(contextPrefix, ipPacket)
}

// SendProxiedIPDatagramNoWake enqueues proxied IP without per-datagram QUIC send wake.
func (s *RequestStream) SendProxiedIPDatagramNoWake(contextPrefix, ipPacket []byte) error {
	return s.str.SendProxiedIPDatagramNoWake(contextPrefix, ipPacket)
}

// SendProxiedIPDatagramInPlaceNoWake enqueues from a caller-owned IP buffer with pool headroom.
func (s *RequestStream) SendProxiedIPDatagramInPlaceNoWake(contextPrefix, ipPacket []byte, release func()) error {
	return s.str.SendProxiedIPDatagramInPlaceNoWake(contextPrefix, ipPacket, release)
}

// FlushProxiedIPDatagramSend schedules one QUIC send after a batched proxied-IP enqueue.
func (s *RequestStream) FlushProxiedIPDatagramSend() {
	s.str.FlushProxiedIPDatagramSend()
}

// ReceiveDatagram receives HTTP Datagrams (RFC 9297).
//
// It is only possible if support for HTTP Datagrams was enabled, using the EnableDatagram
// option on the [Transport].
func (s *RequestStream) ReceiveDatagram(ctx context.Context) ([]byte, error) {
	return s.str.ReceiveDatagram(ctx)
}

// TryReceiveDatagram exposes a non-blocking datagram dequeue (see Stream.TryReceiveDatagram).
func (s *RequestStream) TryReceiveDatagram() ([]byte, bool) {
	return s.str.TryReceiveDatagram()
}

// SendRequestHeader sends the HTTP request.
//
// It can only used for requests that don't have a request body.
// It is invalid to call it more than once.
// It is invalid to call it after Write has been called.
func (s *RequestStream) SendRequestHeader(req *http.Request) error {
	if req.Body != nil && req.Body != http.NoBody {
		return errors.New("http3: invalid use of RequestStream.SendRequestHeader with a request that has a request body")
	}
	return s.sendRequestHeader(req)
}

func (s *RequestStream) sendRequestHeader(req *http.Request) error {
	if s.sentRequest {
		return errors.New("http3: invalid duplicate use of RequestStream.SendRequestHeader")
	}
	if !s.disableCompression && req.Method != http.MethodHead &&
		req.Header.Get("Accept-Encoding") == "" && req.Header.Get("Range") == "" {
		s.requestedGzip = true
	}
	s.isConnect = req.Method == http.MethodConnect
	s.sentRequest = true
	return s.requestWriter.WriteRequestHeader(s.str.datagramStream, req, s.requestedGzip, s.str.StreamID(), s.str.qlogger)
}

// sendRequestTrailer sends request trailers to the stream.
// It should be called after the request body has been fully written.
func (s *RequestStream) sendRequestTrailer(req *http.Request) error {
	return s.requestWriter.WriteRequestTrailer(s.str.datagramStream, req, s.str.StreamID(), s.str.qlogger)
}

// ReadResponse reads the HTTP response from the stream.
//
// It must be called after sending the request (using SendRequestHeader).
// It is invalid to call it more than once.
// It doesn't set Response.Request and Response.TLS.
// It is invalid to call it after Read has been called.
func (s *RequestStream) ReadResponse() (*http.Response, error) {
	if !s.sentRequest {
		return nil, errors.New("http3: invalid use of RequestStream.ReadResponse before SendRequestHeader")
	}
	frame, err := s.str.frameParser.ParseNext(s.str.qlogger)
	if err != nil {
		s.str.CancelRead(quic.StreamErrorCode(ErrCodeFrameError))
		s.str.CancelWrite(quic.StreamErrorCode(ErrCodeFrameError))
		return nil, fmt.Errorf("http3: parsing frame failed: %w", err)
	}
	hf, ok := frame.(*headersFrame)
	if !ok {
		s.str.conn.CloseWithError(quic.ApplicationErrorCode(ErrCodeFrameUnexpected), "expected first frame to be a HEADERS frame")
		return nil, errors.New("http3: expected first frame to be a HEADERS frame")
	}
	if hf.Length > uint64(s.maxHeaderBytes) {
		maybeQlogInvalidHeadersFrame(s.str.qlogger, s.str.StreamID(), hf.Length)
		s.str.CancelRead(quic.StreamErrorCode(ErrCodeFrameError))
		s.str.CancelWrite(quic.StreamErrorCode(ErrCodeFrameError))
		return nil, fmt.Errorf("http3: HEADERS frame too large: %d bytes (max: %d)", hf.Length, s.maxHeaderBytes)
	}
	headerBlock := make([]byte, hf.Length)
	if _, err := io.ReadFull(s.str.datagramStream, headerBlock); err != nil {
		maybeQlogInvalidHeadersFrame(s.str.qlogger, s.str.StreamID(), hf.Length)
		s.str.CancelRead(quic.StreamErrorCode(ErrCodeRequestIncomplete))
		s.str.CancelWrite(quic.StreamErrorCode(ErrCodeRequestIncomplete))
		return nil, fmt.Errorf("http3: failed to read response headers: %w", err)
	}
	decodeFn := s.decoder.Decode(headerBlock)
	var hfs []qpack.HeaderField
	if s.str.qlogger != nil {
		hfs = make([]qpack.HeaderField, 0, 16)
	}
	res := s.response
	err = updateResponseFromHeaders(res, decodeFn, s.maxHeaderBytes, &hfs)
	if s.str.qlogger != nil {
		qlogParsedHeadersFrame(s.str.qlogger, s.str.StreamID(), hf, hfs)
	}
	if err != nil {
		errCode := ErrCodeMessageError
		var qpackErr *qpackError
		if errors.As(err, &qpackErr) {
			errCode = ErrCodeQPACKDecompressionFailed
		}
		s.str.CancelRead(quic.StreamErrorCode(errCode))
		s.str.CancelWrite(quic.StreamErrorCode(errCode))
		return nil, fmt.Errorf("http3: invalid response: %w", err)
	}

	// Check that the server doesn't send more data in DATA frames than indicated by the Content-Length header (if set).
	// See section 4.1.2 of RFC 9114.
	respBody := newResponseBody(s.str, res.ContentLength, s.reqDone)

	// Rules for when to set Content-Length are defined in https://tools.ietf.org/html/rfc7230#section-3.3.2.
	isInformational := res.StatusCode >= 100 && res.StatusCode < 200
	isNoContent := res.StatusCode == http.StatusNoContent
	isSuccessfulConnect := s.isConnect && res.StatusCode >= 200 && res.StatusCode < 300
	if (isInformational || isNoContent || isSuccessfulConnect) && res.ContentLength == -1 {
		res.ContentLength = 0
	}
	if s.requestedGzip && res.Header.Get("Content-Encoding") == "gzip" {
		res.Header.Del("Content-Encoding")
		res.Header.Del("Content-Length")
		res.ContentLength = -1
		s.responseBody = newGzipReader(respBody)
		res.Uncompressed = true
	} else {
		s.responseBody = respBody
	}
	res.Body = s.responseBody
	return res, nil
}

type tracingReader struct {
	io.Reader
	readFirst bool
	trace     *httptrace.ClientTrace
}

func (r *tracingReader) Read(b []byte) (int, error) {
	n, err := r.Reader.Read(b)
	if n > 0 && !r.readFirst {
		traceGotFirstResponseByte(r.trace)
		r.readFirst = true
	}
	return n, err
}
