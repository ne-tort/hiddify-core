package relay

import "testing"

func TestTCPKernelBufExported(t *testing.T) {
	if TCPKernelBuf != 16<<20 {
		t.Fatalf("TCPKernelBuf=%d want %d", TCPKernelBuf, 16<<20)
	}
	if TCPResponseFlushEvery != TCPCopyBufLen {
		t.Fatalf("TCPResponseFlushEvery should match TCPCopyBufLen")
	}
}
