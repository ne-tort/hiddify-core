package netutil

import "testing"

type mockBufferConn struct {
	readBuf, writeBuf int
	noDelay           bool
	noDelaySet        bool
}

func (m *mockBufferConn) SetReadBuffer(n int) error {
	m.readBuf = n
	return nil
}

func (m *mockBufferConn) SetWriteBuffer(n int) error {
	m.writeBuf = n
	return nil
}

func (m *mockBufferConn) SetNoDelay(v bool) error {
	m.noDelay = v
	m.noDelaySet = true
	return nil
}

func TestTuneMasqueUDPSocketBuffers(t *testing.T) {
	t.Parallel()
	var c mockBufferConn
	TuneMasqueUDPSocketBuffers(&c)
	if c.readBuf != MasqueSocketBufferBytes || c.writeBuf != MasqueSocketBufferBytes {
		t.Fatalf("buffers read=%d write=%d want %d", c.readBuf, c.writeBuf, MasqueSocketBufferBytes)
	}
}

func TestTuneMasqueTCPSocketBuffersSetsNagle(t *testing.T) {
	t.Parallel()
	var c mockBufferConn
	TuneMasqueTCPSocketBuffers(&c)
	if c.readBuf != MasqueSocketBufferBytes || c.writeBuf != MasqueSocketBufferBytes {
		t.Fatalf("buffers read=%d write=%d want %d", c.readBuf, c.writeBuf, MasqueSocketBufferBytes)
	}
	if !c.noDelaySet || c.noDelay {
		t.Fatalf("TCP tune want SetNoDelay(false), got set=%v val=%v", c.noDelaySet, c.noDelay)
	}
}
