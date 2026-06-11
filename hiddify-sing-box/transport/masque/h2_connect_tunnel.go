package masque

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"sync"
	"time"

	C "github.com/sagernet/sing-box/constant"
)

// h2ThinTunnelConn is RFC 8441 CONNECT: response body (download) + request pipe (upload).
// No connectauthority, feeder, or duplex — io.Copy hot path only.
type h2ThinTunnelConn struct {
	ctx    context.Context
	reader io.ReadCloser
	upload *io.PipeWriter
	chunk  *h2ConnectChunkedUploadWriter
	local  net.Addr
	remote net.Addr
	uploadDL connDeadlines
	uploadMu sync.Mutex
}

func (c *h2ThinTunnelConn) uploadWriter() io.Writer {
	if c.chunk != nil {
		return c.chunk
	}
	return c.upload
}

func (c *h2ThinTunnelConn) Read(p []byte) (int, error) {
	if c.ctx != nil {
		if err := context.Cause(c.ctx); err != nil {
			return 0, err
		}
	}
	n, err := c.reader.Read(p)
	if err != nil && !errors.Is(err, io.EOF) {
		return n, errors.Join(ErrTCPConnectStreamFailed, err)
	}
	return n, err
}

func (c *h2ThinTunnelConn) Write(p []byte) (int, error) {
	c.uploadMu.Lock()
	defer c.uploadMu.Unlock()
	if c.uploadDL.writeTimeoutExceeded() {
		return 0, errors.Join(ErrTCPConnectStreamFailed, os.ErrDeadlineExceeded)
	}
	if wNanos := c.uploadDL.write.Load(); wNanos != 0 && time.Now().UnixNano() > wNanos {
		return 0, errors.Join(ErrTCPConnectStreamFailed, os.ErrDeadlineExceeded)
	}
	n, err := c.uploadWriter().Write(p)
	if err != nil {
		return n, errors.Join(ErrTCPConnectStreamFailed, err)
	}
	return n, nil
}

func (c *h2ThinTunnelConn) ReadFrom(r io.Reader) (int64, error) {
	c.uploadMu.Lock()
	defer c.uploadMu.Unlock()
	n, err := io.Copy(c.uploadWriter(), r)
	if err != nil {
		return n, errors.Join(ErrTCPConnectStreamFailed, err)
	}
	return n, nil
}

func (c *h2ThinTunnelConn) WriteTo(w io.Writer) (int64, error) {
	n, err := io.Copy(w, c.reader)
	if err != nil && !errors.Is(err, io.EOF) {
		return n, errors.Join(ErrTCPConnectStreamFailed, err)
	}
	return n, err
}

func (c *h2ThinTunnelConn) Close() error {
	// EOF the CONNECT request body before tearing down the response stream so the server
	// relay can finish upload and half-close the target TCP while download drains.
	if c.upload != nil {
		_ = c.upload.Close()
	}
	if c.reader != nil {
		_ = c.reader.Close()
	}
	return nil
}

func (c *h2ThinTunnelConn) CloseWrite() error {
	if c.upload != nil {
		return c.upload.Close()
	}
	return nil
}

func (c *h2ThinTunnelConn) LocalAddr() net.Addr  { return c.local }
func (c *h2ThinTunnelConn) RemoteAddr() net.Addr { return c.remote }

func (c *h2ThinTunnelConn) SetDeadline(t time.Time) error {
	_ = c.SetReadDeadline(t)
	_ = c.SetWriteDeadline(t)
	return nil
}

func (c *h2ThinTunnelConn) SetReadDeadline(t time.Time) error {
	if d, ok := c.reader.(interface{ SetReadDeadline(time.Time) error }); ok {
		return d.SetReadDeadline(t)
	}
	return ErrDeadlineUnsupported
}

func (c *h2ThinTunnelConn) SetWriteDeadline(t time.Time) error {
	c.uploadDL.setWriteDeadline(t)
	return nil
}

func (*h2ThinTunnelConn) RouteConnectionCopyWriterTo() {}

var (
	_ io.ReaderFrom                 = (*h2ThinTunnelConn)(nil)
	_ io.WriterTo                   = (*h2ThinTunnelConn)(nil)
	_ C.RouteConnectionCopyWriterTo = (*h2ThinTunnelConn)(nil)
)

// h2ConnectTunnelFromResponse builds a thin RFC 8441 tunnel after CONNECT succeeds.
func h2ConnectTunnelFromResponse(streamCtx context.Context, resp *http.Response, upload *io.PipeWriter, targetHost string, targetPort uint16) (net.Conn, error) {
	if resp == nil || resp.Body == nil || upload == nil {
		return nil, ErrTCPConnectStreamFailed
	}
	remoteAddr, _ := net.ResolveTCPAddr("tcp", net.JoinHostPort(targetHost, strconv.Itoa(int(targetPort))))
	inner := &h2ThinTunnelConn{
		ctx:    streamCtx,
		reader: newH2ConnectStreamResponseBody(resp.Body),
		upload: upload,
		chunk:  newH2ConnectChunkedUploadWriter(upload),
		local:  &net.TCPAddr{},
		remote: remoteAddr,
	}
	return &connectStreamTunnelConn{inner: inner}, nil
}
