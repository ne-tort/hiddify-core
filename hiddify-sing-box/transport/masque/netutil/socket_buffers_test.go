package netutil

import (
	"context"
	"net"
	"testing"
)

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

func TestTuneMasqueTCPSocketBuffersSetsNagleNotRCVBUF(t *testing.T) {
	t.Parallel()
	var c mockBufferConn
	TuneMasqueTCPSocketBuffers(&c)
	if c.readBuf != 0 {
		t.Fatalf("TCP tune must not SetReadBuffer (got %d); SO_RCVBUF locks break WAN RWND", c.readBuf)
	}
	if c.writeBuf != MasqueSocketBufferBytes {
		t.Fatalf("writeBuf=%d want %d", c.writeBuf, MasqueSocketBufferBytes)
	}
	if !c.noDelaySet || c.noDelay {
		t.Fatalf("TCP tune want SetNoDelay(false), got set=%v val=%v", c.noDelaySet, c.noDelay)
	}
}

func TestMasqueTCPDialerControlSetsSNDBUFNotRCVBUF(t *testing.T) {
	t.Parallel()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, acceptErr := ln.Accept()
		if acceptErr == nil {
			_ = c.Close()
		}
	}()
	d := net.Dialer{Control: MasqueTCPDialerControl}
	conn, err := d.DialContext(context.Background(), "tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	tc, ok := conn.(*net.TCPConn)
	if !ok {
		t.Fatalf("want *net.TCPConn, got %T", conn)
	}
	raw, err := tc.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	snd, err := getSOSndbuf(raw)
	if err != nil {
		t.Skipf("SO_SNDBUF read not available: %v", err)
	}
	if snd < MasqueSocketBufferBytes {
		t.Fatalf("SO_SNDBUF=%d want ≥ %d", snd, MasqueSocketBufferBytes)
	}
	rcv, err := getSORcvbuf(raw)
	if err != nil {
		t.Skipf("SO_RCVBUF read not available: %v", err)
	}
	// Autotune default (not locked to 8 MiB). Windows/Linux defaults are << MasqueSocketBufferBytes*2.
	if rcv >= MasqueSocketBufferBytes*2 {
		t.Fatalf("SO_RCVBUF=%d looks locked to bulk; TCP path must not set SO_RCVBUF", rcv)
	}
}
