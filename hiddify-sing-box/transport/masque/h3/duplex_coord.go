package h3

import (
	"sync/atomic"

	"github.com/quic-go/quic-go"
)

var testBidiDownloadActiveHook func(active bool)

// BidiDuplexCoordEnabled reports whether legacy env-gated duplex_coord queue is active.
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
	if active {
		quic.MasqueSetBidiDownloadReceiveActive(qs, true)
	} else {
		quic.MasqueSetBidiDuplexUploadStarted(qs, false)
		quic.MasqueSetBidiDownloadReceiveActive(qs, false)
	}
}

func (c *TunnelConn) beginDuplexDownload() {
	atomic.StoreInt32(&c.downloadDelivered, 0)
	atomic.StoreInt32(&c.duplexUploadStarted, 0)
	c.maybeSendH3BootstrapBeforeDuplexDownload()
	atomic.AddInt32(&c.downloadActive, 1)
	c.setBidiDownloadActive(true)
}

func (c *TunnelConn) maybeSendH3BootstrapBeforeDuplexDownload() {
	if c == nil || c.h3 == nil || c.routeBidiDuplex {
		// Prod SOCKS/CM always pairs ReaderFrom upload with WriteTo download on one CONNECT
		// stream. Bootstrap zeros before real iperf3 cookie (upload-first) poison docker -R;
		// S2C receive credit is armed at dial via PrimeH3UploadBootstrapOnConn.
		return
	}
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if atomic.LoadInt32(&c.uploadTrafficStarted) == 0 {
		_ = c.sendH3BootstrapUploadUnlocked()
	}
}

func (c *TunnelConn) noteUploadTrafficStarted() {
	if c == nil {
		return
	}
	atomic.StoreInt32(&c.uploadTrafficStarted, 1)
}

func (c *TunnelConn) noteDuplexUploadTraffic() {
	if c == nil || !c.DownloadActive() {
		return
	}
	atomic.StoreInt32(&c.duplexUploadStarted, 1)
	if c.h3 != nil {
		if qs := c.h3.QUICStream(); qs != nil {
			quic.MasqueSetBidiDuplexUploadStarted(qs, true)
		}
	}
}

func (c *TunnelConn) endDuplexDownload() {
	c.setBidiDownloadActive(false)
	atomic.AddInt32(&c.downloadActive, -1)
}

// activateDownloadReceiveOnRead pokes S2C credit on first Read (iperf -R / route Read) without downloadActive wake routing.
func (c *TunnelConn) activateDownloadReceiveOnRead() {
	if c == nil || c.h3 == nil {
		return
	}
	c.downloadReceiveOnce.Do(func() {
		if qs := c.h3.QUICStream(); qs != nil {
			quic.MasqueSetBidiDownloadReceiveActive(qs, true)
			if quic.MasqueDownloadEagerWindowEnabled() {
				quic.MasquePokeDownloadReceiveWindow(qs)
			}
			quic.MasqueWakeStreamSend(qs)
		}
	})
}

func (c *TunnelConn) noteDownloadDelivered() {
	if c == nil || !c.DownloadActive() {
		return
	}
	atomic.StoreInt32(&c.downloadDelivered, 1)
}
