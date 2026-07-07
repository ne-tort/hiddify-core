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
)

// gateH3RelayLeg is an in-process HTTP/3 stream stand-in for synth relay gates.
type gateH3RelayLeg struct {
	r io.Reader
	w io.Writer
}

func (g *gateH3RelayLeg) Read(p []byte) (int, error)  { return g.r.Read(p) }
func (g *gateH3RelayLeg) Write(p []byte) (int, error) { return g.w.Write(p) }
func (g *gateH3RelayLeg) Close() error                 { return nil }

type gateH3RelayLegHost struct {
	leg *gateH3RelayLeg
}

func (h *gateH3RelayLegHost) MasqueRelayCONNECTH3Leg() io.ReadWriteCloser {
	return h.leg
}

// gateH3ReqBody implements io.ReadCloser + RelayCONNECTH3Leg for synth relay gates.
type gateH3ReqBody struct {
	leg *gateH3RelayLeg
}

func (b *gateH3ReqBody) Read(p []byte) (int, error) { return b.leg.Read(p) }
func (b *gateH3ReqBody) Close() error               { return nil }
func (b *gateH3ReqBody) MasqueRelayCONNECTH3Leg() io.ReadWriteCloser {
	return b.leg
}

type gateMemTCPConn struct {
	readPayload []byte
	readOff     int
	writeBuf    bytes.Buffer
	readCalls   atomic.Int32
	closeWriteN atomic.Int32
	closeWriteEarly atomic.Bool
	relayDone   atomic.Bool
	wantRead    int
}

func (c *gateMemTCPConn) Read(p []byte) (int, error) {
	c.readCalls.Add(1)
	if c.readOff >= len(c.readPayload) {
		return 0, io.EOF
	}
	n := copy(p, c.readPayload[c.readOff:])
	c.readOff += n
	return n, nil
}

func (c *gateMemTCPConn) Write(p []byte) (int, error) { return c.writeBuf.Write(p) }
func (c *gateMemTCPConn) Close() error                 { return nil }
func (c *gateMemTCPConn) CloseWrite() error {
	c.closeWriteN.Add(1)
	if !c.relayDone.Load() && c.readOff < c.wantRead && c.wantRead > 0 {
		c.closeWriteEarly.Store(true)
	}
	return nil
}
func (c *gateMemTCPConn) LocalAddr() net.Addr          { return nil }
func (c *gateMemTCPConn) RemoteAddr() net.Addr         { return nil }
func (c *gateMemTCPConn) SetDeadline(time.Time) error  { return nil }
func (c *gateMemTCPConn) SetReadDeadline(time.Time) error {
	return nil
}

type gateDeadlineTCPConn struct {
	gateMemTCPConn
	readDL time.Time
}

func (c *gateDeadlineTCPConn) SetReadDeadline(t time.Time) error {
	c.readDL = t
	return nil
}

// TestGATERelayTunnelUnblockPeerReadClearsDeadline: upload-EOF unblock must not leave i/o timeout on target.
func TestGATERelayTunnelUnblockPeerReadClearsDeadline(t *testing.T) {
	t.Parallel()
	c := &gateDeadlineTCPConn{}
	relayTunnelUnblockPeerRead(c)
	if !c.readDL.IsZero() {
		t.Fatalf("read deadline not cleared after unblock, got %v", c.readDL)
	}
}
func (c *gateMemTCPConn) SetWriteDeadline(time.Time) error { return nil }

func TestRelayH3ConnectModeFromLegRole(t *testing.T) {
	t.Parallel()
	cases := []struct {
		leg  string
		want RelayH3ConnectMode
	}{
		{"", RelayH3ConnectModeBidi},
		{connectStreamLegDownload, RelayH3ConnectModeDownloadLeg},
		{connectStreamLegUpload, RelayH3ConnectModeUploadLeg},
		{"  download  ", RelayH3ConnectModeBidi},
	}
	for _, tc := range cases {
		if got := RelayH3ConnectModeFromLegRole(tc.leg); got != tc.want {
			t.Fatalf("legRole=%q: got %v want %v", tc.leg, got, tc.want)
		}
	}
}

func TestGATERelayH3DownloadLegCopiesTCPToBidiOnly(t *testing.T) {
	t.Parallel()
	const want = "download-payload"
	h3Out := &bytes.Buffer{}
	body := &gateH3ReqBody{leg: &gateH3RelayLeg{w: h3Out, r: bytes.NewReader(nil)}}
	tcp := &gateMemTCPConn{readPayload: []byte(want)}

	err := RelayTCPTunnel(context.Background(), tcp, body, httptest.NewRecorder(), connectStreamLegDownload)
	if err != nil {
		t.Fatalf("RelayTCPTunnel: %v", err)
	}
	if got := h3Out.String(); got != want {
		t.Fatalf("h3 out=%q want %q", got, want)
	}
	if tcp.writeBuf.Len() != 0 {
		t.Fatalf("upload leg wrote to TCP unexpectedly: %q", tcp.writeBuf.Bytes())
	}
}

func TestGATERelayH3UploadLegCopiesBidiToTCPOnly(t *testing.T) {
	t.Parallel()
	const want = "upload-payload"
	tcp := &gateMemTCPConn{}
	body := &gateH3ReqBody{leg: &gateH3RelayLeg{
		r: bytes.NewReader([]byte(want)),
		w: io.Discard,
	}}

	err := RelayTCPTunnel(context.Background(), tcp, body, httptest.NewRecorder(), connectStreamLegUpload)
	if err != nil {
		t.Fatalf("RelayTCPTunnel: %v", err)
	}
	if got := tcp.writeBuf.String(); got != want {
		t.Fatalf("tcp out=%q want %q", got, want)
	}
	if tcp.readCalls.Load() != 0 {
		t.Fatal("download leg read from onward TCP on upload-only relay")
	}
}

func TestGATERelayH3BidiLegRunsBothDirections(t *testing.T) {
	t.Parallel()
	tcp := &gateMemTCPConn{readPayload: []byte("down")}
	h3Up := &bytes.Buffer{}
	body := &gateH3ReqBody{leg: &gateH3RelayLeg{
		r: bytes.NewReader([]byte("up")),
		w: h3Up,
	}}

	err := RelayTCPTunnel(context.Background(), tcp, body, httptest.NewRecorder(), "")
	if err != nil {
		t.Fatalf("RelayTCPTunnel: %v", err)
	}
	if h3Up.String() != "down" {
		t.Fatalf("bidi download h3=%q", h3Up.String())
	}
	if tcp.writeBuf.String() != "up" {
		t.Fatalf("bidi upload tcp=%q", tcp.writeBuf.String())
	}
}
