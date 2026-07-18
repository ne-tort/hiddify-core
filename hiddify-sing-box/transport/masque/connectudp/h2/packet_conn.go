package h2

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/transport/masque/connectudp/flowstats"
	"github.com/sagernet/sing-box/transport/masque/connectudp/frame"
	"github.com/sagernet/sing-box/transport/masque/connectudp/split"
	h2c "github.com/sagernet/sing-box/transport/masque/h2"
)

type PacketConnConfig struct {
	ReqPipeR      io.Closer
	ReqBody       io.WriteCloser
	Resp          *http.Response
	LocalAddr     net.Addr
	RemoteAddr    net.Addr
	UploadWireAck h2c.ConnectUploadWireAck
	OnClose       func()
}

// PacketConn is the client CONNECT-UDP net.PacketConn over one HTTP/2 stream (RFC 9298).
// WriteTo → request body DATAGRAM capsules; ReadFrom ← response body.
type PacketConn struct {
	reqPipeR io.Closer
	reqBody  io.WriteCloser
	resp     *http.Response

	respBodyBuf *bufio.Reader
	// downlinkPending holds unconsumed RFC9297 wire bytes (h2o scan-loop buffer).
	downlinkPending bytes.Buffer

	writeMu sync.Mutex
	readMu  sync.Mutex
	// bodyReadMu serializes bufio reads on the response body.
	bodyReadMu sync.Mutex

	downlinkReadBuf []byte

	// uploadPending holds encoded RFC9297 wire bytes before flush (Close / wake).
	uploadPending bytes.Buffer

	deadlines    split.ConnDeadlines
	closed       atomic.Bool
	closeOnce    sync.Once
	duplexActive atomic.Bool
	payloadWritePending atomic.Bool

	primeOnce sync.Once
	primeErr  error

	uploadWireAck       h2c.ConnectUploadWireAck
	uploadWireCommitted atomic.Int64

	localAddr  net.Addr
	remoteAddr net.Addr
	onClose    func()
}

// NewPacketConn builds a CONNECT-UDP packet conn (thin sync bidi — approach A).
func NewPacketConn(cfg PacketConnConfig) *PacketConn {
	c := &PacketConn{
		reqPipeR:      cfg.ReqPipeR,
		reqBody:       cfg.ReqBody,
		resp:          cfg.Resp,
		localAddr:     cfg.LocalAddr,
		remoteAddr:    cfg.RemoteAddr,
		uploadWireAck: cfg.UploadWireAck,
		onClose:       cfg.OnClose,
	}
	return c
}

// IsClosed reports whether Close has been called (test hook).
func (c *PacketConn) IsClosed() bool { return c.closed.Load() }

func (c *PacketConn) LocalAddr() net.Addr  { return c.localAddr }
func (c *PacketConn) RemoteAddr() net.Addr { return c.remoteAddr }

func (c *PacketConn) SetDeadline(t time.Time) error {
	c.deadlines.SetDeadline(t)
	return nil
}

func (c *PacketConn) SetReadDeadline(t time.Time) error {
	c.deadlines.SetReadDeadline(t)
	return nil
}

func (c *PacketConn) SetWriteDeadline(t time.Time) error {
	c.deadlines.SetWriteDeadline(t)
	return nil
}

func (c *PacketConn) Close() error {
	c.closeOnce.Do(func() {
		if c == nil {
			return
		}
		c.closed.Store(true)
		c.writeMu.Lock()
		wire := c.takeUploadPendingLocked()
		c.writeMu.Unlock()
		if len(wire) > 0 {
			if err := c.flushUploadWire(wire); err != nil {
				flowstats.RecordClientC2SFail()
			}
		}
		// Half-close upload: mark done + close writer so http2 can drain remaining pipe
		// bytes to TLS. Do NOT close the pipe reader here — that discards unread buf
		// (write_ok already counted) and races writeRequestBody (ErrClosedPipe).
		if c.uploadWireAck != nil {
			if done, ok := c.uploadWireAck.(interface{ MarkUploadWriterDone() }); ok {
				done.MarkUploadWriterDone()
			}
		}
		committed := c.uploadWireCommitted.Load()
		if c.reqBody != nil {
			_ = c.reqBody.Close()
			c.reqBody = nil
		}
		if c.uploadWireAck != nil && committed > 0 {
			// Best-effort barrier: prefer delivering committed capsules over fast teardown.
			_ = c.uploadWireAck.AwaitUploadWireSent(committed, 2*time.Second)
		}
		wireSent := int64(0)
		pipeBuf := 0
		if c.uploadWireAck != nil {
			if u, ok := c.uploadWireAck.(interface{ UploadWireSent() int64 }); ok {
				wireSent = u.UploadWireSent()
			}
		}
		if c.reqPipeR != nil {
			if u, ok := c.reqPipeR.(interface{ MasqueUploadBuffered() int }); ok {
				pipeBuf = u.MasqueUploadBuffered()
			}
		}
		flowstats.LogClientStatsDetailed("h2-bidi", flowstats.Detail{
			WireSentBytes:      wireSent,
			WireCommittedBytes: committed,
			PipeBufferedBytes:  pipeBuf,
		})
		// Reader is owned by http2 RoundTrip; leave it for the transport. Drop our ref only.
		c.reqPipeR = nil
		// Peer peel barrier: do NOT read/close resp.Body yet. SOCKS keeps ReadFrom blocked on
		// Body; closing it (or interruptBlockedBodyRead) sends RST and reintroduces pre_server
		// loss at 400–500+ Mbit. Wait for server uplink to finish request END_STREAM, then cancel.
		time.Sleep(uploadPeerPeelGrace(committed))
		if c.resp != nil && c.resp.Body != nil {
			_ = c.resp.Body.Close()
		}
		if c.onClose != nil {
			c.onClose()
		}
	})
	return nil
}

// uploadPeerPeelGrace is how long Close waits after upload END_STREAM before cancelling the
// stream. Scaled by committed wire bytes at ~200 Mbit peel rate.
//
// Microflows (DNS-sized committed): near-zero grace — MCS slot occupancy from Close sleep is
// not a real prod risk at MCS=1000, but 500ms min was pure teardown latency tax. Bulk keeps
// the longer barrier that fixed pre_server loss @400–500+.
func uploadPeerPeelGrace(committedBytes int64) time.Duration {
	const (
		microThreshold = 64 << 10 // 64 KiB wire — DNS / short ASSOCIATE
		microGrace     = 20 * time.Millisecond
		minBulkGrace   = 500 * time.Millisecond
		maxGrace       = 3 * time.Second
		peelBit        = 200e6 // bits/s
	)
	if committedBytes <= 0 || committedBytes < microThreshold {
		return microGrace
	}
	ns := float64(committedBytes) * 8 / peelBit * float64(time.Second)
	d := time.Duration(ns)
	if d < minBulkGrace {
		return minBulkGrace
	}
	if d > maxGrace {
		return maxGrace
	}
	return d
}

// FlushC2SWrites drains any pending upload wire (probe / echo parity).
func (c *PacketConn) FlushC2SWrites() {
	if c == nil || c.closed.Load() {
		return
	}
	c.writeMu.Lock()
	wire := c.takeUploadPendingLocked()
	c.writeMu.Unlock()
	if len(wire) > 0 {
		if err := c.flushUploadWire(wire); err != nil {
			flowstats.RecordClientC2SFail()
		}
	}
}

func (c *PacketConn) AwaitUploadDrain(timeout time.Duration) error {
	if c == nil || c.closed.Load() {
		return nil
	}
	c.FlushC2SWrites()
	n := c.uploadWireCommitted.Load()
	c.writeMu.Lock()
	if c.reqBody != nil {
		_ = c.reqBody.Close()
		c.reqBody = nil
	}
	c.writeMu.Unlock()
	if c.uploadWireAck != nil && n > 0 {
		return c.uploadWireAck.AwaitUploadWireSent(n, timeout)
	}
	return nil
}

func (c *PacketConn) noteUploadWireCommitted(n int) {
	if c != nil && n > 0 {
		c.uploadWireCommitted.Add(int64(n))
	}
}

func (c *PacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	if c.resp == nil || c.resp.Body == nil {
		return 0, nil, fmt.Errorf("masque h2 dataplane connect-udp: missing HTTP response body")
	}
	hadPayloadWrite := c.payloadWritePending.Load()
	if hadPayloadWrite {
		c.duplexActive.Store(true)
		if err := c.flushUploadPendingForRead(); err != nil {
			return 0, nil, err
		}
	}
	if c.closed.Load() {
		return 0, nil, net.ErrClosed
	}
	ctx := context.Background()
	readCancel := func() {}
	if v := c.deadlines.Read.Load(); v != 0 {
		if time.Now().UnixNano() > v {
			return 0, nil, os.ErrDeadlineExceeded
		}
		ctx, readCancel = context.WithDeadline(context.Background(), time.Unix(0, v))
	}
	defer readCancel()

	c.readMu.Lock()
	n, err := c.readH2DatagramIntoLocked(p, ctx)
	c.readMu.Unlock()
	if err != nil {
		if errors.Is(err, split.ErrPortUnreachable) {
			return 0, c.remoteAddr, split.NewPortUnreachableError(c.remoteAddr)
		}
		return 0, nil, err
	}
	if n > 0 {
		c.duplexActive.Store(true)
	}
	return n, c.remoteAddr, nil
}

func (c *PacketConn) WriteTo(p []byte, _ net.Addr) (int, error) {
	if c.closed.Load() {
		return 0, net.ErrClosed
	}
	if c.deadlines.WriteTimeoutExceeded() {
		return 0, os.ErrDeadlineExceeded
	}

	c.writeMu.Lock()
	if c.closed.Load() {
		c.writeMu.Unlock()
		return 0, net.ErrClosed
	}
	if c.deadlines.WriteTimeoutExceeded() {
		c.writeMu.Unlock()
		return 0, os.ErrDeadlineExceeded
	}
	if len(p) == 0 {
		pending := c.takeUploadPendingLocked()
		c.writeMu.Unlock()
		if err := c.flushUploadWire(pending); err != nil {
			flowstats.RecordClientC2SFail()
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrClosedPipe) {
				return 0, err
			}
			_ = c.Close()
			return 0, fmt.Errorf("masque h2 dataplane connect-udp write body: %w", err)
		}
		if err := c.writeEmptyDatagramCapsule(); err != nil {
			flowstats.RecordClientC2SFail()
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrClosedPipe) {
				return 0, err
			}
			_ = c.Close()
			return 0, fmt.Errorf("masque h2 dataplane connect-udp write body: %w", err)
		}
		return 0, nil
	}

	// Thin sync bidi: immediate capsule write (unlock before blocking http2 Write).
	c.writeMu.Unlock()
	if err := c.writeUploadUDPPayloadUnlocked(p); err != nil {
		if errors.Is(err, frame.ErrProxiedUDPPayloadTooLarge) {
			flowstats.RecordClientC2SOversize()
			return 0, err
		}
		flowstats.RecordClientC2SFail()
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrClosedPipe) {
			return 0, err
		}
		if errors.Is(err, os.ErrDeadlineExceeded) || errors.Is(err, context.Canceled) {
			return 0, err
		}
		_ = c.Close()
		return 0, fmt.Errorf("masque h2 dataplane connect-udp write body: %w", err)
	}
	flowstats.RecordClientC2SOK()
	c.payloadWritePending.Store(true)
	return len(p), nil
}
