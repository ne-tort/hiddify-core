package connectip

import "testing"

func TestSelfHosted(t *testing.T) {
	if SelfHosted(true) {
		t.Fatal("expected false when Warp client cert is present")
	}
	if !SelfHosted(false) {
		t.Fatal("expected true when Warp client cert is absent")
	}
}

func TestUDPWriteHardCapFor(t *testing.T) {
	if got := UDPWriteHardCapFor(false); got != UDPWriteHardCap {
		t.Fatalf("wan: got %d want %d", got, UDPWriteHardCap)
	}
	if got := UDPWriteHardCapFor(true); got != LabUDPWriteHardCap {
		t.Fatalf("self-hosted: got %d want %d", got, LabUDPWriteHardCap)
	}
	if LabUDPWriteHardCap != UDPWriteHardCap {
		t.Fatalf("lab and wan caps must match current policy: lab=%d wan=%d", LabUDPWriteHardCap, UDPWriteHardCap)
	}
}

func TestTCPHTTP3DatagramSlack(t *testing.T) {
	if TCPHTTP3DatagramSlack != 128 {
		t.Fatalf("unexpected slack: got %d want 128", TCPHTTP3DatagramSlack)
	}
}
