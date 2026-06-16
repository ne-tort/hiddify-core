package stream

import (
	"io"
	"net/http"
)

// relayTunnelWakeH2AfterUploadRead flushes the H2 CONNECT response after server consumes client
// upload bytes (plain HTTP/2 relay fallback).
func relayTunnelWakeH2AfterUploadRead(responseWriter http.ResponseWriter) {
	if responseWriter == nil {
		return
	}
	relayTunnelFlushNow(responseWriter, responseWriter)
}

// relayTunnelWakeH2AfterDownloadWrite flushes the H2 CONNECT response after download bytes are
// queued toward the client (plain HTTP/2 relay fallback).
func relayTunnelWakeH2AfterDownloadWrite(responseWriter http.ResponseWriter) {
	if responseWriter == nil {
		return
	}
	relayTunnelFlushNow(responseWriter, responseWriter)
}

// relayTunnelCopyBufferH2BidiUpload copies client upload → onward TCP with per-chunk H2 flush.
func relayTunnelCopyBufferH2BidiUpload(dst io.Writer, src io.Reader, responseWriter http.ResponseWriter) (int64, error) {
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
				relayTunnelWakeH2AfterUploadRead(responseWriter)
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

// relayTunnelCopyBufferH2BidiDownload copies onward TCP → CONNECT response with per-chunk H2 flush.
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
