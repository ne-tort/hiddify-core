package relay

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
)

type gateH3RelayLeg struct {
	r io.Reader
	w io.Writer
}

func (l *gateH3RelayLeg) Read(p []byte) (int, error)  { return l.r.Read(p) }
func (l *gateH3RelayLeg) Write(p []byte) (int, error) { return l.w.Write(p) }
func (l *gateH3RelayLeg) Close() error                { return nil }

// gateH3CloseTrackBody fails Close if download payload is incomplete (early H3 cancel).
type gateH3CloseTrackBody struct {
	leg           *gateH3RelayLeg
	wantDownload  int
	downloadBytes atomic.Int32
	closeN        atomic.Int32
	closedEarly   atomic.Bool
}

func (b *gateH3CloseTrackBody) Read(p []byte) (int, error) { return b.leg.Read(p) }
func (b *gateH3CloseTrackBody) Close() error {
	b.closeN.Add(1)
	if int(b.downloadBytes.Load()) < b.wantDownload {
		b.closedEarly.Store(true)
	}
	return nil
}
func (b *gateH3CloseTrackBody) MasqueRelayCONNECTH3Leg() io.ReadWriteCloser { return b.leg }

type gateCountWriter struct {
	dst   *bytes.Buffer
	bytes *atomic.Int32
}

func (w *gateCountWriter) Write(p []byte) (int, error) {
	w.bytes.Add(int32(len(p)))
	return w.dst.Write(p)
}

func gateH3TrackDownloadBody(uploadR io.Reader, wantDownload int) (*gateH3CloseTrackBody, *bytes.Buffer) {
	h3Out := &bytes.Buffer{}
	body := &gateH3CloseTrackBody{wantDownload: wantDownload}
	cw := &gateCountWriter{dst: h3Out, bytes: &body.downloadBytes}
	body.leg = &gateH3RelayLeg{r: uploadR, w: cw}
	return body, h3Out
}

// TestGATERelayH3BidiUploadEOFBeforeDownloadDoneNoEarlyBodyClose (P0 RELAY-H3-TEARDOWN):
// upload leg EOF (iperf -R cookie shape) must not Close reqBody while download relay runs.
// CloseWrite on onward TCP after upload EOF is required (iperf control half-close) and may
// precede download completion.
func TestGATERelayH3BidiUploadEOFBeforeDownloadDoneNoEarlyBodyClose(t *testing.T) {
	t.Parallel()
	const payloadLen = 256 * 1024
	uploadR := io.MultiReader(bytes.NewReader([]byte("FAKEIPERF")), bytes.NewReader(nil))
	body, h3Out := gateH3TrackDownloadBody(uploadR, payloadLen)
	tcp := &gateMemTCPConn{readPayload: bytes.Repeat([]byte("d"), payloadLen), wantRead: payloadLen}

	err := RelayTCPTunnel(context.Background(), tcp, body, httptest.NewRecorder())
	tcp.relayDone.Store(true)
	if err != nil {
		t.Fatalf("RelayTCPTunnel: %v", err)
	}
	if body.closedEarly.Load() {
		t.Fatalf("reqBody.Close before download complete (%d/%d bytes)", body.downloadBytes.Load(), payloadLen)
	}
	if h3Out.Len() != payloadLen {
		t.Fatalf("download relayed %d bytes want %d", h3Out.Len(), payloadLen)
	}
	if body.closeN.Load() != 0 {
		t.Fatalf("hijacked H3 relay must not Close reqBody, got %d", body.closeN.Load())
	}
}

type gateMemTCPConn struct {
	readPayload []byte
	wantRead    int
	off         int
	relayDone   atomic.Bool
}

func (c *gateMemTCPConn) Read(p []byte) (int, error) {
	if c.off >= len(c.readPayload) {
		return 0, io.EOF
	}
	n := copy(p, c.readPayload[c.off:])
	c.off += n
	return n, nil
}
func (c *gateMemTCPConn) Write(p []byte) (int, error) { return len(p), nil }
func (c *gateMemTCPConn) Close() error                { return nil }
func (c *gateMemTCPConn) CloseWrite() error           { return nil }
func (c *gateMemTCPConn) LocalAddr() net.Addr         { return nil }
func (c *gateMemTCPConn) RemoteAddr() net.Addr        { return nil }
func (c *gateMemTCPConn) SetDeadline(time.Time) error      { return nil }
func (c *gateMemTCPConn) SetReadDeadline(time.Time) error  { return nil }
func (c *gateMemTCPConn) SetWriteDeadline(time.Time) error { return nil }

// gateSlowTCPConn yields TCP payload in small chunks to keep download relay active.
type gateSlowTCPConn struct {
	payload         []byte
	off             int
	closeWriteN     atomic.Int32
	closeWriteEarly atomic.Bool
	relayDone       atomic.Bool
}

func (c *gateSlowTCPConn) Read(p []byte) (int, error) {
	if c.off >= len(c.payload) {
		return 0, io.EOF
	}
	chunk := min(4096, len(c.payload)-c.off)
	n := copy(p, c.payload[c.off:c.off+chunk])
	c.off += n
	time.Sleep(time.Millisecond)
	return n, nil
}
func (c *gateSlowTCPConn) Write(p []byte) (int, error) { return len(p), nil }
func (c *gateSlowTCPConn) Close() error               { return nil }
func (c *gateSlowTCPConn) CloseWrite() error {
	c.closeWriteN.Add(1)
	if !c.relayDone.Load() && c.off < len(c.payload) {
		c.closeWriteEarly.Store(true)
	}
	return nil
}
func (c *gateSlowTCPConn) LocalAddr() net.Addr        { return nil }
func (c *gateSlowTCPConn) RemoteAddr() net.Addr       { return nil }
func (c *gateSlowTCPConn) SetDeadline(time.Time) error      { return nil }
func (c *gateSlowTCPConn) SetReadDeadline(time.Time) error  { return nil }
func (c *gateSlowTCPConn) SetWriteDeadline(time.Time) error { return nil }

// TestGATERelayH3BidiSlowDownloadSurvivesUploadEOF: sustained download after upload EOF.
func TestGATERelayH3BidiSlowDownloadSurvivesUploadEOF(t *testing.T) {
	t.Parallel()
	const payloadLen = 128 * 1024
	body, h3Out := gateH3TrackDownloadBody(bytes.NewReader([]byte("cookie")), payloadLen)
	tcp := &gateSlowTCPConn{payload: bytes.Repeat([]byte("x"), payloadLen)}

	start := time.Now()
	err := RelayTCPTunnel(context.Background(), tcp, body, httptest.NewRecorder())
	tcp.relayDone.Store(true)
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("RelayTCPTunnel: %v", err)
	}
	if body.closedEarly.Load() {
		t.Fatalf("reqBody.Close before slow download complete (%d/%d bytes)", body.downloadBytes.Load(), payloadLen)
	}
	if h3Out.Len() != payloadLen {
		t.Fatalf("download relayed %d bytes want %d", h3Out.Len(), payloadLen)
	}
	if elapsed < 20*time.Millisecond {
		t.Fatalf("slow download gate too fast (%v)", elapsed)
	}
}

// TestGATERelayTunnelSelectNilReqBodyDownloadErrorNoPanic: hijacked H3 passes nil reqBody.
// Early download error must still wait for the upload leg (slot recycle).
func TestGATERelayTunnelSelectNilReqBodyDownloadErrorNoPanic(t *testing.T) {
	t.Parallel()
	uploadErrCh := make(chan error, 1)
	downloadErrCh := make(chan error, 1)
	downloadErrCh <- io.ErrClosedPipe
	uploadErrCh <- nil
	tcp := &gateMemTCPConn{}
	err := relayTunnelSelect(context.Background(), tcp, nil, uploadErrCh, downloadErrCh, nil)
	if err == nil {
		t.Fatal("want download error")
	}
}

type gateH3AbortTrackLeg struct {
	uploadR      io.Reader
	downloadW    io.Writer
	cancelReadN  atomic.Int32
	closeN       atomic.Int32
	unblockRead  chan struct{}
}

func (l *gateH3AbortTrackLeg) Read(p []byte) (int, error) {
	if l.unblockRead != nil {
		<-l.unblockRead
	}
	if l.uploadR == nil {
		return 0, io.EOF
	}
	return l.uploadR.Read(p)
}
func (l *gateH3AbortTrackLeg) Write(p []byte) (int, error) {
	if l.downloadW == nil {
		return 0, io.ErrClosedPipe
	}
	return l.downloadW.Write(p)
}
func (l *gateH3AbortTrackLeg) Close() error {
	l.closeN.Add(1)
	l.wakeRead()
	return nil
}
func (l *gateH3AbortTrackLeg) CancelRead(_ quic.StreamErrorCode) {
	l.cancelReadN.Add(1)
	l.wakeRead()
}
func (l *gateH3AbortTrackLeg) wakeRead() {
	if l.unblockRead == nil {
		return
	}
	select {
	case <-l.unblockRead:
	default:
		close(l.unblockRead)
	}
}

// TestGATERelayH3BidiDownloadAbortCancelsReceiveHalf: download error must CancelRead so
// a blocked upload Read wakes and the QUIC stream can leave MaxIncomingStreams.
func TestGATERelayH3BidiDownloadAbortCancelsReceiveHalf(t *testing.T) {
	t.Parallel()
	leg := &gateH3AbortTrackLeg{
		uploadR:     bytes.NewReader(nil), // blocks until CancelRead/Close wakes Read
		downloadW:   &bytes.Buffer{},
		unblockRead: make(chan struct{}),
	}
	// Infinite block on upload Read until CancelRead; download fails immediately via bad target.
	tcp := &gateFailWriteTCPConn{}

	done := make(chan error, 1)
	go func() {
		done <- RelayTCPTunnelBidiStream(context.Background(), tcp, nil, leg)
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("want download error")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("relay hung after download abort (upload Read not woken)")
	}
	if leg.cancelReadN.Load() == 0 {
		t.Fatal("expected CancelRead on H3 bidi after abort")
	}
	if leg.closeN.Load() == 0 {
		t.Fatal("expected Close on H3 bidi after abort")
	}
}

type gateFailWriteTCPConn struct {
	gateMemTCPConn
}

func (c *gateFailWriteTCPConn) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }
func (c *gateFailWriteTCPConn) Read([]byte) (int, error)  { return 0, io.ErrUnexpectedEOF }
