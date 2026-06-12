package h2

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/http"

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
	return cip.H2MaxCapsulePayload(cip.DatagramCeilingMax())
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

// FlushRequestBody flushes CONNECT-UDP uplink request bodies when supported.
func FlushRequestBody(w io.Writer) {
	if w == nil {
		return
	}
	if f, ok := w.(interface{ Flush() error }); ok {
		_ = f.Flush()
	}
}

// WriteDatagramCapsule serializes one RFC 9297 DATAGRAM capsule (context id 0 + UDP payload).
func WriteDatagramCapsule(w io.Writer, udpPayload []byte) error {
	dgram := make([]byte, 1+len(udpPayload))
	dgram[0] = 0
	copy(dgram[1:], udpPayload)
	var buf bytes.Buffer
	if err := writeCapsule(&buf, CapsuleTypeDatagram, dgram); err != nil {
		return err
	}
	if _, err := WriteAll(w, buf.Bytes()); err != nil {
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
	if len(udpPayload) == 0 {
		return WriteDatagramCapsule(w, nil)
	}
	step := MaxUDPPayloadPerDatagramCapsule()
	for offset := 0; offset < len(udpPayload); {
		end := offset + step
		if end > len(udpPayload) {
			end = len(udpPayload)
		}
		if err := WriteDatagramCapsule(w, udpPayload[offset:end]); err != nil {
			return err
		}
		offset = end
	}
	return nil
}
