package tun

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestKernelTunDeviceBatchOnlyReadContract locks HP-4b6: prod host-kernel egress uses ReadEgressBatch only;
// ReadPacket delegates; no readOneAccepted N× fallback loop.
func TestKernelTunDeviceBatchOnlyReadContract(t *testing.T) {
	t.Parallel()
	src := readTunSource(t, "kernel_tun_device.go")
	if strings.Contains(src, "readOneAccepted") {
		t.Fatal("readOneAccepted removed — batch-only ReadEgressBatch")
	}
	if strings.Contains(src, "d.readLocked(ctx, buf)") && strings.Contains(src, "func (d *KernelTunDevice) ReadPacket") {
		// ReadPacket must not syscall-read directly; only ReadEgressBatch.
		rp := src[strings.Index(src, "func (d *KernelTunDevice) ReadPacket"):]
		if end := strings.Index(rp, "\nfunc "); end > 0 {
			rp = rp[:end]
		}
		if strings.Contains(rp, "readLocked") || strings.Contains(rp, "shouldRelayHostEgress") {
			t.Fatal("ReadPacket must delegate to ReadEgressBatch, not duplicate egress accept loop")
		}
	}
	if !strings.Contains(src, "ReadEgressBatch(ctx, slot, 1)") {
		t.Fatal("ReadPacket must delegate to ReadEgressBatch")
	}
}

func readTunSource(t *testing.T, name string) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(wd, name))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
