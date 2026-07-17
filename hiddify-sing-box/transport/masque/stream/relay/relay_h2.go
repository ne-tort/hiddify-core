package relay

import (
	"errors"
	"io"
	"net"
	"net/http"
	"time"
)

// h2DownloadFillWait is the inter-Read gap budget after the first byte while filling
// RelayTunnelBufLen. CF onward is bursty: 2 ms truncated fills to ~1.4 MiB → plat~320 @30ms
// despite a 4 MiB ceiling; 10 ms bridges typical WAN gaps without Flush-less S3 coalesce.
const h2DownloadFillWait = 10 * time.Millisecond

// h2DownloadFlushMinBytes: on Read timeout, keep accumulating below this mark until
// h2DownloadFillMaxWall (avoid micro-chunk stop-wait; quantum is below RelayTunnelBufLen).
const h2DownloadFlushMinBytes = 256 << 10

// h2DownloadFillMaxWall caps how long we hold a partial before Flush (TTFB / latency).
const h2DownloadFillMaxWall = 40 * time.Millisecond

func relayTunnelCopyBufferH2BidiUpload(dst io.Writer, src io.Reader) (int64, error) {
	bp := relayTunnelBufPool.Get().(*[]byte)
	defer relayTunnelBufPool.Put(bp)
	return io.CopyBuffer(dst, src, *bp)
}

func relayTunnelClearReadDeadline(src net.Conn) {
	_ = src.SetReadDeadline(time.Time{})
}

func relayDownloadBuf(pol H2DownloadPolicy) (buf []byte, put func()) {
	if pol.BufferBytes <= 0 || pol.BufferBytes == RelayTunnelBufLen {
		bp := relayTunnelBufPool.Get().(*[]byte)
		return *bp, func() { relayTunnelBufPool.Put(bp) }
	}
	b := make([]byte, pol.BufferBytes)
	return b, func() {}
}

// relayTunnelCopyBufferH2BidiDownload fills up to policy BufferBytes from onward TCP
// (short coalesce wait after the first byte), then one Write + Flush.
// Per-short-Read Flush made CF __down stop-wait at ~256KiB/RTT (~54 Mbit @~39 ms);
// iperf fill stayed high because onward stays saturated. Prime path still Flush-on-Write.
func relayTunnelCopyBufferH2BidiDownload(dst io.Writer, src net.Conn, responseWriter http.ResponseWriter) (int64, error) {
	pol := currentH2DownloadPolicy()
	buf, put := relayDownloadBuf(pol)
	defer put()
	var written int64
	for {
		off := 0
		var er error
		var fillStart time.Time
		for off < len(buf) {
			if off > 0 {
				if fillStart.IsZero() {
					fillStart = time.Now()
				}
				_ = src.SetReadDeadline(time.Now().Add(pol.FillWait))
			}
			var nr int
			nr, er = src.Read(buf[off:])
			if nr > 0 {
				off += nr
			}
			if er != nil {
				if ne, ok := er.(net.Error); ok && ne.Timeout() &&
					off > 0 && off < pol.FlushMinBytes &&
					!fillStart.IsZero() && time.Since(fillStart) < pol.FillMaxWall {
					er = nil
					continue
				}
				break
			}
		}
		relayTunnelClearReadDeadline(src)

		if off > 0 {
			nw, ew := dst.Write(buf[:off])
			if nw > 0 {
				written += int64(nw)
				if responseWriter != nil {
					relayTunnelFlushNow(responseWriter, responseWriter)
				}
			}
			if ew != nil {
				return written, ew
			}
			if off != nw {
				return written, io.ErrShortWrite
			}
		}
		if er != nil {
			if errors.Is(er, io.EOF) {
				return written, nil
			}
			if ne, ok := er.(net.Error); ok && ne.Timeout() {
				continue
			}
			return written, er
		}
	}
}

func relayTunnelDownloadRelayH2(out io.Writer, responseWriter http.ResponseWriter, src net.Conn) (int64, error) {
	var written int64
	if prime, err := relayTunnelPrimeDownload(src); err != nil {
		return 0, err
	} else if len(prime) > 0 {
		if _, err := out.Write(prime); err != nil {
			return int64(len(prime)), err
		}
		written += int64(len(prime))
		relayTunnelFlushNow(out, responseWriter)
	}
	n, err := relayTunnelCopyBufferH2BidiDownload(out, src, responseWriter)
	written += n
	if err != nil && !errors.Is(err, io.EOF) {
		return written, err
	}
	relayTunnelFlushNow(out, responseWriter)
	return written, nil
}
