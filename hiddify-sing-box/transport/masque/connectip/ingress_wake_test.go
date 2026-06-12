package connectip

import "testing"

func TestIngressAckWakeFromPacket(t *testing.T) {
	ackPkt := buildTestIPv4TCP(t, 0x10, nil)
	synPkt := buildTestIPv4TCP(t, 0x02, nil)

	var w IngressAckWake
	w.NoteFromPacket(synPkt)
	if w.Pending() {
		t.Fatal("SYN-only must not schedule wake")
	}

	w.NoteFromPacket(ackPkt)
	if !w.Pending() {
		t.Fatal("ACK candidate must schedule wake")
	}
	if !w.TakePending() {
		t.Fatal("TakePending must succeed once")
	}
	if w.Pending() {
		t.Fatal("wake must be cleared after take")
	}
	if w.TakePending() {
		t.Fatal("second TakePending must fail")
	}
}

func TestIngressAckWakeSchedule(t *testing.T) {
	var w IngressAckWake
	w.Schedule()
	if !w.Pending() {
		t.Fatal("Schedule must mark pending")
	}
	if !w.TakePending() {
		t.Fatal("TakePending must consume scheduled wake")
	}
}
