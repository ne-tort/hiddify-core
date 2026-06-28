package egress

import (
	"testing"
)

type flushRecordingHost struct {
	conn *flushRecordingConn
}

type flushRecordingConn struct {
	flushCount int
}

func (c *flushRecordingConn) WritePacketNoWake([]byte) ([]byte, error) { return nil, nil }
func (c *flushRecordingConn) WritePacket([]byte) ([]byte, error)       { return nil, nil }
func (c *flushRecordingConn) WritePacketInPlaceNoWake([]byte) ([]byte, bool, error) {
	return nil, false, nil
}
func (c *flushRecordingConn) WritePacketPrefixed([]byte) ([]byte, error) { return nil, nil }
func (c *flushRecordingConn) FlushOutgoingDatagramSend()                   { c.flushCount++ }

func (h *flushRecordingHost) PacketConn() PacketConn { return h.conn }
func (h *flushRecordingHost) DatagramCeiling() int   { return 1500 }
func (h *flushRecordingHost) WakeAfterDatagram() func() { return nil }

func TestWritePacketFlushesTransport(t *testing.T) {
	conn := &flushRecordingConn{}
	h := &flushRecordingHost{conn: conn}
	pkt := make([]byte, 40)
	pkt[0] = 0x45
	pkt[9] = 6
	if _, err := WritePacket(h, pkt); err != nil {
		t.Fatalf("WritePacket: %v", err)
	}
	if conn.flushCount != 1 {
		t.Fatalf("FlushOutgoingDatagramSend=%d want 1 after WritePacket", conn.flushCount)
	}
}
