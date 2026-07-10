package stream

import "testing"

func TestConnectStreamUseDualConnectDefault(t *testing.T) {
	t.Setenv(envConnectStreamDualConnect, "")
	if ConnectStreamUseDualConnect() {
		t.Fatal("prod default must be single bidi CONNECT")
	}
}

func TestConnectStreamUseDualConnectOptIn(t *testing.T) {
	t.Setenv(envConnectStreamDualConnect, "1")
	if !ConnectStreamUseDualConnect() {
		t.Fatal("env=1 must enable dual CONNECT")
	}
}
