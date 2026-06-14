package h3

import (
	"io"
	"sync/atomic"

	"github.com/quic-go/quic-go"
	strm "github.com/sagernet/sing-box/transport/masque/stream"
)

const envH3BidiDuplexCoord = "MASQUE_H3_BIDI_DUPLEX_COORD" // retained for test env hygiene only

var testBidiDownloadActiveHook func(active bool)

// peerDuplexDownloadLeg reports P2 download CONNECT (upload runs on sibling stream).
func (c *TunnelConn) peerDuplexDownloadLeg() bool {
	return c != nil && c.connectStreamLeg == strm.ConnectStreamLegDownload
}

// sameStreamDuplexUploadWake reports whether WriteTo should poke upload on this stream
// (false on P2 download leg — sibling upload CONNECT owns C2S wake).
func (c *TunnelConn) sameStreamDuplexUploadWake() bool {
	return c != nil && !c.peerDuplexDownloadLeg()
}

// BidiDuplexCoordEnabled reports whether legacy coordinated upload queue is active.
// Always false: prod upload during download WriteTo writes directly to h3.
func BidiDuplexCoordEnabled() bool { return false }

// DownloadActive reports whether WriteTo is draining the response half (iperf -R duplex).
func (c *TunnelConn) DownloadActive() bool {
	return c != nil && atomic.LoadInt32(&c.downloadActive) > 0
}

// DownloadDelivered reports whether WriteTo delivered at least one response byte (true duplex interleave).
func (c *TunnelConn) DownloadDelivered() bool {
	return c != nil && atomic.LoadInt32(&c.downloadDelivered) > 0
}

func (c *TunnelConn) setBidiDownloadActive(active bool) {
	if c == nil || c.h3 == nil {
		return
	}
	if testBidiDownloadActiveHook != nil {
		testBidiDownloadActiveHook(active)
	}
	qs := c.h3.QUICStream()
	if qs == nil {
		return
	}
	if c.connectStreamLeg == strm.ConnectStreamLegDownload {
		quic.MasqueSetBidiDownloadReceiveActive(qs, active)
		return
	}
	quic.MasqueSetBidiDownloadActive(qs, active)
}

func (c *TunnelConn) beginDuplexDownload() {
	atomic.StoreInt32(&c.downloadDelivered, 0)
	atomic.StoreInt32(&c.duplexUploadStarted, 0)
	atomic.AddInt32(&c.downloadActive, 1)
	c.setBidiDownloadActive(true)
}

func (c *TunnelConn) noteDuplexUploadTraffic() {
	if c != nil && c.DownloadActive() {
		atomic.StoreInt32(&c.duplexUploadStarted, 1)
	}
}

func (c *TunnelConn) endDuplexDownload() {
	c.setBidiDownloadActive(false)
	atomic.AddInt32(&c.downloadActive, -1)
}

func (c *TunnelConn) noteDownloadDelivered() {
	if c == nil || !c.DownloadActive() {
		return
	}
	atomic.StoreInt32(&c.downloadDelivered, 1)
}

// interleaveDuplexTransfer drains pending upload between download reads on one goroutine.
func interleaveDuplexTransfer(
	w io.Writer,
	readFn func([]byte) (int, error),
	flushUpload func() error,
	buf []byte,
	afterDownload func(wrote int),
) (int64, error) {
	var total int64
	for {
		if err := flushUpload(); err != nil {
			return total, err
		}
		n, err := readFn(buf)
		if n > 0 {
			wrote, werr := w.Write(buf[:n])
			total += int64(wrote)
			if werr != nil {
				return total, werr
			}
			if wrote < n {
				return total, io.ErrShortWrite
			}
			if afterDownload != nil && wrote > 0 {
				afterDownload(wrote)
			}
		}
		if err != nil {
			if err == io.EOF {
				_ = flushUpload()
				return total, nil
			}
			return total, err
		}
	}
}
