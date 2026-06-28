package forwarder

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// TestConnectIPForwarderSRPContract locks W-IP-2 file boundaries (IP-SOLID-03 AUDIT).
func TestConnectIPForwarderSRPContract(t *testing.T) {
	t.Parallel()
	layers := map[string][]string{
		"read":     {"tcp_forwarder.go"},
		"write":    {"tcp_forwarder_write.go"},
		"ack":      {"tcp_forwarder_ack.go"},
		"syn":      {"tcp_forwarder_syn.go"},
		"session":  {"tcp_session.go"},
		"segment":  {"packet_tcp.go"},
		"udp":      {"udp_forwarder.go", "packet_udp.go"},
		"policy":   {"policy.go", "peersnat.go"},
	}
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	root := filepath.Dir(filename)
	for layer, files := range layers {
		for _, f := range files {
			path := filepath.Join(root, f)
			if _, err := os.Stat(path); err != nil {
				t.Fatalf("layer %q missing %s: %v", layer, f, err)
			}
		}
	}
	readSrc, err := os.ReadFile(filepath.Join(root, "tcp_forwarder.go"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(readSrc), "func RunConnectIPTCPPacketPlaneForwarder") {
		t.Fatal("tcp_forwarder.go must own RunConnectIPTCPPacketPlaneForwarder")
	}
	writeSrc, err := os.ReadFile(filepath.Join(root, "tcp_forwarder_write.go"))
	if err != nil {
		t.Fatal(err)
	}
	for _, sym := range []string{"runEgressLoop", "runWriteLoop", "runDownloadWriteLoop", "sendPacketNow"} {
		if !strings.Contains(string(writeSrc), sym) {
			t.Fatalf("tcp_forwarder_write.go must own %q", sym)
		}
	}
}
