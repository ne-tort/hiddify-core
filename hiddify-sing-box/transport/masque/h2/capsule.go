package h2

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"

	"github.com/dunglas/httpsfv"
	cip "github.com/sagernet/sing-box/transport/masque/connectip"
	"github.com/quic-go/quic-go/quicvarint"
)

// CapsuleType is an RFC 9297 capsule type on HTTP/2 Extended CONNECT streams.
type CapsuleType uint64

const (
	// CapsuleTypeDatagram is RFC 9297 DATAGRAM (0x00).
	CapsuleTypeDatagram CapsuleType = 0x00
	// NondatagramMaxCapsulePayload caps declared length for non-DATAGRAM RFC 9297 capsules.
	NondatagramMaxCapsulePayload = 65536
)

// ErrOversizedDeclared tags rejections of hostile capsule length varints before any body I/O.
var ErrOversizedDeclared = errors.New("masque h2 connect-udp oversized capsule declaration")

// MaxCapsulePayload bounds DATAGRAM capsule declared length on the wire (parity with ServeH2ConnectUDP).
func MaxCapsulePayload() int {
	return cip.H2MaxCapsulePayload(cip.DefaultDatagramCeilingMax)
}

// MaxUDPPayloadPerDatagramCapsule is the largest UDP payload per RFC 9297 DATAGRAM capsule.
func MaxUDPPayloadPerDatagramCapsule() int {
	return MaxCapsulePayload() - 1
}

var capsuleProtoHeaderValue = func() string {
	v, err := httpsfv.Marshal(httpsfv.NewItem(true))
	if err != nil {
		return "?1"
	}
	return v
}()

// CapsuleProtocolHeaderValue returns the Capsule-Protocol structured field for Extended CONNECT over HTTP/2.
func CapsuleProtocolHeaderValue() string {
	return capsuleProtoHeaderValue
}

type capsuleExactReader struct {
	R io.LimitedReader
}

func (r *capsuleExactReader) Read(b []byte) (int, error) {
	n, err := r.R.Read(b)
	if err == io.EOF && r.R.N > 0 {
		return n, io.ErrUnexpectedEOF
	}
	return n, err
}

type countingVarintReader struct {
	wrapped quicvarint.Reader
	num     int
}

func (w *countingVarintReader) ReadByte() (byte, error) {
	b, err := w.wrapped.ReadByte()
	if err == nil {
		w.num++
	}
	return b, err
}

func (w *countingVarintReader) Read(p []byte) (int, error) {
	n, err := w.wrapped.Read(p)
	w.num += n
	return n, err
}

func writeCapsule(w quicvarint.Writer, ct CapsuleType, value []byte) error {
	b := make([]byte, 0, 16)
	b = quicvarint.Append(b, uint64(ct))
	b = quicvarint.Append(b, uint64(len(value)))
	if _, err := w.Write(b); err != nil {
		return err
	}
	_, err := w.Write(value)
	return err
}

// ParseCapsule is like quic-go http3.ParseCapsule plus a declared-length cap before body reads.
func ParseCapsule(r quicvarint.Reader) (CapsuleType, io.Reader, error) {
	cr := &countingVarintReader{wrapped: r}
	ctUint, err := quicvarint.Read(cr)
	if err != nil {
		if err == io.EOF && cr.num > 0 {
			return 0, nil, io.ErrUnexpectedEOF
		}
		return 0, nil, err
	}
	length, err := quicvarint.Read(cr)
	if err != nil {
		if err == io.EOF && cr.num > 0 {
			return 0, nil, io.ErrUnexpectedEOF
		}
		return 0, nil, err
	}
	maxPayload := MaxCapsulePayload()
	ct := CapsuleType(ctUint)
	if ct == CapsuleTypeDatagram {
		if length > uint64(maxPayload) {
			return 0, nil, fmt.Errorf("%w: DATAGRAM capsule payload exceeds %d bytes",
				ErrOversizedDeclared, maxPayload)
		}
	} else if length > uint64(NondatagramMaxCapsulePayload) {
		return 0, nil, fmt.Errorf("%w: non-datagram capsule exceeds %d bytes",
			ErrOversizedDeclared, NondatagramMaxCapsulePayload)
	}
	return ct, &capsuleExactReader{R: io.LimitedReader{R: r, N: int64(length)}}, nil
}

// ParseNextDatagramCapsuleWire parses one RFC9297 capsule prefix from wire.
// Returns consumed=0 when wire is truncated (caller should read more). For non-DATAGRAM
// capsules inner is nil and the full capsule is skipped via consumed.
func ParseNextDatagramCapsuleWire(wire []byte) (inner []byte, consumed int, err error) {
	if len(wire) == 0 {
		return nil, 0, nil
	}
	ct, n1, err := quicvarint.Parse(wire)
	if err != nil {
		if errors.Is(err, io.EOF) {
			return nil, 0, nil
		}
		return nil, 0, err
	}
	if n1 >= len(wire) {
		return nil, 0, nil
	}
	length, n2, err := quicvarint.Parse(wire[n1:])
	if err != nil {
		if errors.Is(err, io.EOF) {
			return nil, 0, nil
		}
		return nil, 0, err
	}
	headerLen := n1 + n2
	total := headerLen + int(length)
	if total < headerLen || len(wire) < total {
		return nil, 0, nil
	}
	if CapsuleType(ct) != CapsuleTypeDatagram {
		if length > uint64(NondatagramMaxCapsulePayload) {
			return nil, 0, fmt.Errorf("%w: non-datagram capsule exceeds %d bytes",
				ErrOversizedDeclared, NondatagramMaxCapsulePayload)
		}
		return nil, total, nil
	}
	if length > uint64(MaxCapsulePayload()) {
		return nil, 0, fmt.Errorf("%w: DATAGRAM capsule payload exceeds %d bytes",
			ErrOversizedDeclared, MaxCapsulePayload())
	}
	return wire[headerLen:total], total, nil
}

var capsulePayloadPool = sync.Pool{
	New: func() any {
		b := make([]byte, MaxCapsulePayload())
		return &b
	},
}

// ReadCapsulePayload reads the declared capsule body from ParseCapsule's reader.
// release returns the backing buffer to a pool; omit calling release when payload is retained.
func ReadCapsulePayload(r io.Reader) (payload []byte, release func(), err error) {
	nop := func() {}
	er, ok := r.(*capsuleExactReader)
	if !ok {
		p, err := io.ReadAll(r)
		return p, nop, err
	}
	n := int(er.R.N)
	if n <= 0 {
		return nil, nop, nil
	}
	bp := capsulePayloadPool.Get().(*[]byte)
	buf := *bp
	if cap(buf) < n {
		buf = make([]byte, n)
	}
	payload = buf[:n]
	if _, err := io.ReadFull(r, payload); err != nil {
		*bp = buf[:0]
		capsulePayloadPool.Put(bp)
		return nil, nop, err
	}
	return payload, func() {
		*bp = buf[:0]
		capsulePayloadPool.Put(bp)
	}, nil
}

// WriteAll writes all of p to w per the io.Writer contract (partial writes without error).
func WriteAll(w io.Writer, p []byte) (int, error) {
	if w == nil {
		return 0, errors.New("nil writer")
	}
	nn := 0
	for nn < len(p) {
		n, err := w.Write(p[nn:])
		nn += n
		if err != nil {
			return nn, err
		}
		if n == 0 {
			return nn, io.ErrShortWrite
		}
	}
	return nn, nil
}

// FlushResponse pushes RFC 9297 capsules on HTTP/2 Extended CONNECT response bodies.
func FlushResponse(w io.Writer) {
	if w == nil {
		return
	}
	if rw, ok := w.(http.ResponseWriter); ok {
		if err := http.NewResponseController(rw).Flush(); err == nil || errors.Is(err, http.ErrNotSupported) {
			return
		}
	}
	if flusher, ok := w.(http.Flusher); ok {
		flusher.Flush()
	}
}

// FlushRequestBody flushes Extended CONNECT uplink request bodies when supported.
// CONNECT-IP H2 upload is usually *io.PipeWriter (no flush); consume-only poke is safe.
func FlushRequestBody(w io.Writer) {
	if w == nil {
		return
	}
	if f, ok := w.(interface{ Flush() error }); ok {
		_ = f.Flush()
		return
	}
	if flusher, ok := w.(http.Flusher); ok {
		flusher.Flush()
	}
}

// AppendDatagramCapsuleWire serializes one RFC 9297 DATAGRAM capsule without flushing.
func AppendDatagramCapsuleWire(w io.Writer, udpPayload []byte) error {
	dgramLen := 1 + len(udpPayload)
	hdrLen := quicvarint.Len(uint64(CapsuleTypeDatagram)) + quicvarint.Len(uint64(dgramLen))
	total := hdrLen + dgramLen
	if total <= 2048 {
		var scratch [2048]byte
		wire := appendDatagramCapsuleWireBytes(scratch[:0], udpPayload)
		_, err := WriteAll(w, wire)
		return err
	}
	wire := appendDatagramCapsuleWireBytes(make([]byte, 0, total), udpPayload)
	_, err := WriteAll(w, wire)
	return err
}

func appendDatagramCapsuleWireBytes(dst []byte, udpPayload []byte) []byte {
	dgramLen := 1 + len(udpPayload)
	dst = quicvarint.Append(quicvarint.Append(dst, uint64(CapsuleTypeDatagram)), uint64(dgramLen))
	dst = append(dst, 0)
	return append(dst, udpPayload...)
}

// Wire prefix for synth bench 512 B UDP payload (RFC9297 DATAGRAM ctx 0); suffix is raw UDP bytes.
var datagramCapsule512Prefix = func() []byte {
	wire := appendDatagramCapsuleWireBytes(nil, make([]byte, 512))
	return append([]byte(nil), wire[:len(wire)-512]...)
}()

// DatagramCapsule512WireLen is the on-wire byte length of one 512 B UDP DATAGRAM capsule (synth bench shape).
var DatagramCapsule512WireLen = len(datagramCapsule512Prefix) + 512

// CountLeadingDatagramCapsule512Wire counts consecutive synth-shape 512 B capsules at the start of wire.
func CountLeadingDatagramCapsule512Wire(wire []byte) int {
	n := 0
	for {
		_, consumed, ok := TryConsumeDatagramCapsule512Wire(wire)
		if !ok || consumed == 0 {
			break
		}
		n++
		wire = wire[consumed:]
	}
	return n
}

// TryConsumeDatagramCapsule512Wire fast-parses a fixed-size 512 B UDP DATAGRAM capsule (ctx 0).
// Returns consumed=0 when wire does not match the synth bench shape — caller falls back to generic parse.
func TryConsumeDatagramCapsule512Wire(wire []byte) (udpPayload []byte, consumed int, ok bool) {
	if len(wire) < DatagramCapsule512WireLen {
		return nil, 0, false
	}
	if wire[0] != 0 || wire[3] != 0 {
		return nil, 0, false
	}
	if !bytes.Equal(wire[:len(datagramCapsule512Prefix)], datagramCapsule512Prefix) {
		return nil, 0, false
	}
	off := len(datagramCapsule512Prefix)
	return wire[off : off+512], DatagramCapsule512WireLen, true
}

// AppendDatagramCapsuleBuffer appends one RFC 9297 DATAGRAM capsule into dst without WriteAll scratch.
func AppendDatagramCapsuleBuffer(dst *bytes.Buffer, udpPayload []byte) {
	if dst == nil {
		return
	}
	if len(udpPayload) == 512 {
		dst.Grow(len(datagramCapsule512Prefix) + 512)
		dst.Write(datagramCapsule512Prefix)
		dst.Write(udpPayload)
		return
	}
	dgramLen := 1 + len(udpPayload)
	hdrLen := quicvarint.Len(uint64(CapsuleTypeDatagram)) + quicvarint.Len(uint64(dgramLen))
	dst.Grow(hdrLen + dgramLen)
	wire := appendDatagramCapsuleWireBytes(dst.AvailableBuffer()[:0], udpPayload)
	dst.Write(wire)
}

// AppendUDPPayloadAsDatagramCapsules splits a UDP payload into DATAGRAM capsules without flushing.
func AppendUDPPayloadAsDatagramCapsules(w io.Writer, udpPayload []byte) error {
	if len(udpPayload) == 0 {
		return AppendDatagramCapsuleWire(w, nil)
	}
	step := MaxUDPPayloadPerDatagramCapsule()
	for offset := 0; offset < len(udpPayload); {
		end := offset + step
		if end > len(udpPayload) {
			end = len(udpPayload)
		}
		if err := AppendDatagramCapsuleWire(w, udpPayload[offset:end]); err != nil {
			return err
		}
		offset = end
	}
	return nil
}

// WriteDatagramCapsule serializes one RFC 9297 DATAGRAM capsule (context id 0 + UDP payload).
// G54: flushes once per capsule (burst/interactive path). Batch callers use Append* + one terminal flush.
func WriteDatagramCapsule(w io.Writer, udpPayload []byte) error {
	if err := AppendDatagramCapsuleWire(w, udpPayload); err != nil {
		return err
	}
	if rw, ok := w.(http.ResponseWriter); ok {
		FlushResponse(rw)
	} else {
		FlushRequestBody(w)
	}
	return nil
}

// WriteUDPPayloadAsDatagramCapsules splits a UDP payload into a sequence of DATAGRAM capsules.
func WriteUDPPayloadAsDatagramCapsules(w io.Writer, udpPayload []byte) error {
	if err := AppendUDPPayloadAsDatagramCapsules(w, udpPayload); err != nil {
		return err
	}
	if rw, ok := w.(http.ResponseWriter); ok {
		FlushResponse(rw)
	} else {
		FlushRequestBody(w)
	}
	return nil
}
