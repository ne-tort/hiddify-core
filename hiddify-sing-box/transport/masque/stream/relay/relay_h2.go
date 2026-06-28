package relay

import (
	"errors"
	"io"
	"net"
	"net/http"
)

func relayTunnelWakeH2AfterUploadRead(responseWriter http.ResponseWriter) {
	if responseWriter == nil {
		return
	}
	relayTunnelFlushNow(responseWriter, responseWriter)
}

func relayTunnelWakeH2AfterDownloadWrite(responseWriter http.ResponseWriter) {
	if responseWriter == nil {
		return
	}
	relayTunnelFlushNow(responseWriter, responseWriter)
}

func relayTunnelCopyBufferH2BidiUpload(dst io.Writer, src io.Reader, responseWriter http.ResponseWriter) (int64, error) {
	bp := relayTunnelBufPool.Get().(*[]byte)
	defer relayTunnelBufPool.Put(bp)
	buf := *bp
	var written int64
	var pendingWake int
	flushWake := func(force bool) {
		if responseWriter == nil || pendingWake <= 0 {
			return
		}
		if !force && pendingWake < RelayTunnelUploadWakeBytes {
			return
		}
		pendingWake = 0
		relayTunnelWakeH2AfterUploadRead(responseWriter)
	}
	for {
		nr, er := src.Read(buf)
		if nr > 0 {
			nw, ew := dst.Write(buf[:nr])
			if nw > 0 {
				written += int64(nw)
				pendingWake += nw
				flushWake(false)
			}
			if ew != nil {
				flushWake(true)
				return written, ew
			}
			if nr != nw {
				flushWake(true)
				return written, io.ErrShortWrite
			}
		}
		if er != nil {
			flushWake(true)
			if er == io.EOF {
				return written, nil
			}
			return written, er
		}
	}
}

func relayTunnelCopyBufferH2BidiDownload(dst io.Writer, src io.Reader, responseWriter http.ResponseWriter) (int64, error) {
	bp := relayTunnelBufPool.Get().(*[]byte)
	defer relayTunnelBufPool.Put(bp)
	buf := *bp
	var written int64
	for {
		nr, er := src.Read(buf)
		if nr > 0 {
			nw, ew := dst.Write(buf[:nr])
			if nw > 0 {
				written += int64(nw)
				relayTunnelWakeH2AfterDownloadWrite(responseWriter)
			}
			if ew != nil {
				return written, ew
			}
			if nr != nw {
				return written, io.ErrShortWrite
			}
		}
		if er != nil {
			if er == io.EOF {
				return written, nil
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
		relayTunnelFlushFinal(out, responseWriter)
	}
	n, err := relayTunnelCopyBufferH2BidiDownload(out, src, responseWriter)
	written += n
	if err != nil && !errors.Is(err, io.EOF) {
		return written, err
	}
	relayTunnelFlushFinal(out, responseWriter)
	return written, nil
}
