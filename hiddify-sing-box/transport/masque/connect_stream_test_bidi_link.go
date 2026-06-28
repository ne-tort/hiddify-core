package masque

import (
	"io"
	"net"
	"time"

	mh2 "github.com/sagernet/sing-box/transport/masque/h2"
	"github.com/sagernet/sing-box/transport/masque/h3"
)

const (
	localizeBenchRTT             = 35 * time.Millisecond
	localizeBenchWindowBytes     = 64 * 1024
	localizeBenchWindowL256Bytes = 256 * 1024
	localizeBenchWindowWideBytes = 16 << 20
	localizeBenchDuration        = 400 * time.Millisecond
	localizeBenchMinBytes        = 32 * 1024
)

// bidiLink models the HTTP/3 CONNECT-stream bidi byte pipe for localize benches.
type bidiLink interface {
	wrap(net.Conn) net.Conn
}

type instantBidiLink struct{}

func (instantBidiLink) wrap(c net.Conn) net.Conn { return c }

// readAsWriterTo adapts Read-path TCP for WriteTo bench parity on L0.
type readAsWriterTo struct{ net.Conn }

func (c readAsWriterTo) WriteTo(w io.Writer) (int64, error) { return io.Copy(w, c.Conn) }

// benchConnWriteTo adapts Read-path TCP for WriteTo bench with prod-sized copy buffer (256 KiB).
type benchConnWriteTo struct{ net.Conn }

func (c benchConnWriteTo) WriteTo(w io.Writer) (int64, error) {
	buf := make([]byte, 256*1024)
	return io.CopyBuffer(w, c.Conn, buf)
}

// windowedBidiLink limits per-direction in-flight bytes (Write=C2S, Read=S2C) and returns
// credit after RTT (bench-shaped ~64 KiB / RTT ≈ 13–15 Mbit/s at 35 ms).
type windowedBidiLink struct {
	rtt              time.Duration
	windowBytes      int
	noLimitS2C       bool
	instantCredit    bool
	instantCreditS2C bool
}

func (w windowedBidiLink) wrap(inner net.Conn) net.Conn {
	return h3.WrapBidiWindow(inner, h3.BidiWindowConfig{
		RTT:              w.rtt,
		WindowBytes:      w.windowBytes,
		NoLimitS2C:       w.noLimitS2C,
		InstantCredit:    w.instantCredit,
		InstantCreditS2C: w.instantCreditS2C,
	})
}

func bypassB2BidiLink() windowedBidiLink {
	return windowedBidiLink{
		rtt:         localizeBenchRTT,
		windowBytes: localizeBenchWindowBytes,
		noLimitS2C:  true,
	}
}

func bypassB7BidiLink() windowedBidiLink {
	return windowedBidiLink{
		rtt:           localizeBenchRTT,
		windowBytes:   localizeBenchWindowBytes,
		instantCredit: true,
	}
}

func bypassB8BidiLink() windowedBidiLink {
	return windowedBidiLink{
		rtt:         40 * time.Millisecond,
		windowBytes: localizeBenchWindowBytes,
	}
}

// benchWindowedBidiLinkStrict models HTTP/2-style bidi FC without prod eager S2C WINDOW.
func benchWindowedBidiLinkStrict() windowedBidiLink {
	link := windowedBidiLink{
		rtt:         localizeBenchRTT,
		windowBytes: localizeBenchWindowBytes,
	}
	if mh2.DownloadEagerWindowEnabled() {
		link.instantCreditS2C = true
	}
	return link
}

// benchWindowedBidiLinkH2Prod applies H2-specific eager download window for windowed KPI tests.
func benchWindowedBidiLinkH2Prod() windowedBidiLink {
	link := windowedBidiLink{
		rtt:         localizeBenchRTT,
		windowBytes: localizeBenchWindowBytes,
	}
	if mh2.DownloadEagerWindowEnabled() {
		link.instantCreditS2C = true
	}
	return link
}

func benchWindowedBidiLink() windowedBidiLink {
	link := windowedBidiLink{
		rtt:         localizeBenchRTT,
		windowBytes: localizeBenchWindowBytes,
	}
	if h3.DownloadEagerWindowEnabled() {
		link.instantCreditS2C = true
	}
	return link
}

// benchWindowedBidiLinkStrictH3 models QUIC bidi FC without prod eager S2C instant credit.
func benchWindowedBidiLinkStrictH3() windowedBidiLink {
	return windowedBidiLink{
		rtt:         localizeBenchRTT,
		windowBytes: localizeBenchWindowBytes,
	}
}

// benchWindowedBidiLinkStrictH3L256 is strict H3 bidi FC at 256 KiB window (~58 Mbit/s @ 35 ms).
func benchWindowedBidiLinkStrictH3L256() windowedBidiLink {
	return windowedBidiLink{
		rtt:         localizeBenchRTT,
		windowBytes: localizeBenchWindowL256Bytes,
	}
}

// benchWindowedBidiLinkH3Prod applies prod eager S2C window on strict H3 bidi link (H2 P1c parity).
func benchWindowedBidiLinkH3Prod() windowedBidiLink {
	link := benchWindowedBidiLinkStrictH3()
	if h3.DownloadEagerWindowEnabled() {
		link.instantCreditS2C = true
	}
	return link
}

func benchWindowedWideBidiLink() windowedBidiLink {
	return windowedBidiLink{
		rtt:         localizeBenchRTT,
		windowBytes: localizeBenchWindowWideBytes,
	}
}

func benchWindowedBidiLinkL256() windowedBidiLink {
	return windowedBidiLink{
		rtt:         localizeBenchRTT,
		windowBytes: localizeBenchWindowL256Bytes,
	}
}
