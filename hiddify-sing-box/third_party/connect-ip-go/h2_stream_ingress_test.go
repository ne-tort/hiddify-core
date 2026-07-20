package connectip

import (
	"bytes"
	"io"
	"testing"
)

func TestH2BulkIngressDispatchesDatagram(t *testing.T) {
	bodyR, bodyW := io.Pipe()
	str := &h2CapsulePipeStream{
		body:  bodyR,
		pipeW: io.Discard,
	}
	conn := newProxiedConn(str, true)
	defer conn.Close()
	defer bodyR.Close()
	defer bodyW.Close()

	ipPacket := make([]byte, 540)
	wire := bytes.NewBuffer(nil)
	dgramPayload := composeProxiedIPDatagramPayload(contextIDZero, ipPacket)
	if err := appendHTTPDatagramCapsule(wire, dgramPayload); err != nil {
		t.Fatal(err)
	}
	if _, err := bodyW.Write(wire.Bytes()); err != nil {
		t.Fatal(err)
	}

	out := make([]byte, len(ipPacket)+8)
	n, err := conn.ReadPacket(out)
	if err != nil || n != len(ipPacket) {
		t.Fatalf("ReadPacket n=%d err=%v", n, err)
	}
}

func TestTryDispatchPartialWireNeedsMore(t *testing.T) {
	conn := &Conn{datagramCapsuleIngress: make(chan []byte, 1)}
	partial := []byte{0x00} // truncated varint capsule header
	if _, err := conn.tryDispatchOneCapsuleFromWire(partial); err != errNeedMoreStreamWire {
		t.Fatalf("got err=%v want errNeedMoreStreamWire", err)
	}
}

func TestTryDispatchFullDatagramCapsule(t *testing.T) {
	conn := &Conn{datagramCapsuleIngress: make(chan []byte, 1)}
	ip := []byte{0x45, 0x00}
	payload := composeProxiedIPDatagramPayload(contextIDZero, ip)
	var wire bytes.Buffer
	if err := appendHTTPDatagramCapsule(&wire, payload); err != nil {
		t.Fatal(err)
	}
	consumed, err := conn.tryDispatchOneCapsuleFromWire(wire.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if consumed != wire.Len() {
		t.Fatalf("consumed=%d want %d", consumed, wire.Len())
	}
	select {
	case got := <-conn.datagramCapsuleIngress:
		if !bytes.Equal(got, payload) {
			t.Fatalf("payload mismatch")
		}
	default:
		t.Fatal("expected ingress enqueue")
	}
}
