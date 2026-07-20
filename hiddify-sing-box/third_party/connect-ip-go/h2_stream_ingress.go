package connectip

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"log"
	"time"

	"github.com/quic-go/quic-go/http3"
)

// h2StreamReadBufSize coalesces HTTP/2 CONNECT response-body reads (CONNECT-UDP parity).
const h2StreamReadBufSize = 256 * 1024

var errNeedMoreStreamWire = errors.New("connect-ip: partial stream capsule wire")

type wireVarintReader struct {
	wire []byte
	off  int
}

func (r *wireVarintReader) ReadByte() (byte, error) {
	if r.off >= len(r.wire) {
		return 0, io.EOF
	}
	b := r.wire[r.off]
	r.off++
	return b, nil
}

func (r *wireVarintReader) Read(p []byte) (int, error) {
	if r.off >= len(r.wire) {
		return 0, io.EOF
	}
	n := copy(p, r.wire[r.off:])
	r.off += n
	return n, nil
}

func isPartialStreamCapsuleErr(err error) bool {
	return errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, errNeedMoreStreamWire)
}

func (c *Conn) readFromStreamH2Bulk() error {
	if c.h2IngressBR == nil {
		c.h2IngressBR = bufio.NewReaderSize(c.str, h2StreamReadBufSize)
	}
	if cap(c.h2IngressScratch) < h2StreamReadBufSize {
		c.h2IngressScratch = make([]byte, h2StreamReadBufSize)
	}
	for {
		for c.h2IngressPending.Len() > 0 {
			consumed, err := c.tryDispatchOneCapsuleFromWire(c.h2IngressPending.Bytes())
			if isPartialStreamCapsuleErr(err) {
				break
			}
			if err != nil {
				if errors.Is(err, io.EOF) {
					return err
				}
				return wrapConnectIPStreamDataplaneErr(c, err)
			}
			if consumed <= 0 {
				break
			}
			c.h2IngressPending.Next(consumed)
		}
		c.compactH2IngressPending()

		n, err := c.h2IngressBR.Read(c.h2IngressScratch)
		if n > 0 {
			_, _ = c.h2IngressPending.Write(c.h2IngressScratch[:n])
			continue
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				if c.h2IngressPending.Len() > 0 {
					return wrapConnectIPStreamDataplaneErr(c, io.ErrUnexpectedEOF)
				}
				return err
			}
			return wrapConnectIPStreamDataplaneErr(c, err)
		}
	}
}

func (c *Conn) compactH2IngressPending() {
	if c.h2IngressPending.Len() == 0 && c.h2IngressPending.Cap() > h2StreamReadBufSize*2 {
		c.h2IngressPending = bytes.Buffer{}
	}
}

func (c *Conn) tryDispatchOneCapsuleFromWire(wire []byte) (int, error) {
	if len(wire) == 0 {
		return 0, errNeedMoreStreamWire
	}
	wr := &wireVarintReader{wire: wire}
	t, cr, err := parseConnectIPStreamCapsule(wr)
	if err != nil {
		if isPartialStreamCapsuleErr(err) {
			return 0, errNeedMoreStreamWire
		}
		return 0, err
	}
	if err := c.dispatchStreamCapsule(t, cr); err != nil {
		if isPartialStreamCapsuleErr(err) {
			return 0, errNeedMoreStreamWire
		}
		return 0, err
	}
	return wr.off, nil
}

func (c *Conn) dispatchStreamCapsule(t http3.CapsuleType, cr io.Reader) error {
	switch t {
	case capsuleTypeHTTPDatagram:
		parseStart := time.Now()
		payload, err := readRFC9297HTTPDatagramCapsulePayload(cr)
		recordH2ClientCapsuleReadParse(parseStart)
		if err != nil {
			return err
		}
		if c.datagramCapsuleIngress != nil {
			c.ensureH2CapsuleIngressPrefetchDrainer()
			recordH2ClientIngressEnqueue(payload)
			select {
			case <-c.closeChan:
				return c.errAfterClose()
			case c.datagramCapsuleIngress <- payload:
			default:
				if !c.enqueueH2CapsuleIngressWithBackpressure(payload) {
					logSampledDrop(&streamCapsuleDatagramIngressDropTotal, "connect-ip: dropped stream HTTP_DATAGRAM capsule (h2 capsule ingress full)")
				}
			}
			return nil
		}
		if c.h3UnifiedDatagramIngress != nil {
			recordH2ClientIngressEnqueue(payload)
			select {
			case <-c.closeChan:
				return c.errAfterClose()
			case c.h3UnifiedDatagramIngress <- payload:
			default:
				if !c.enqueueH3UnifiedIngressWithBackpressure(payload) {
					logSampledDrop(&streamCapsuleDatagramIngressDropTotal, "connect-ip: dropped stream HTTP_DATAGRAM capsule (h3 unified ingress full)")
				}
			}
			return nil
		}
		return nil
	case capsuleTypeAddressAssign:
		return c.dispatchAddressAssignCapsule(cr)
	case capsuleTypeAddressRequest:
		return c.dispatchAddressRequestCapsule(cr)
	case capsuleTypeRouteAdvertisement:
		return c.dispatchRouteAdvertisementCapsule(cr)
	default:
		unknownCapsuleTotal.Add(1)
		incrementUnknownCapsuleType(t)
		if _, copyErr := io.Copy(io.Discard, cr); copyErr != nil {
			return copyErr
		}
		log.Printf("connect-ip: ignoring unknown capsule type=%d", t)
		return nil
	}
}
