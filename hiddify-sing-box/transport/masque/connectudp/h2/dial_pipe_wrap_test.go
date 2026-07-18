package h2

import (
	"testing"

	h2c "github.com/sagernet/sing-box/transport/masque/h2"
)

func TestConnectUDPNoXNetBulkPipeForwardsBufferedAndWake(t *testing.T) {
	t.Parallel()
	pr, pw := h2c.NewConnectUploadShallowPipe()
	t.Cleanup(func() {
		_ = pw.Close()
		_ = pr.Close()
	})
	wrapped := wrapConnectUDPNoXNetBulkPipe(pr)
	if got := wrapped.(interface{ UploadPipeCap() int }).UploadPipeCap(); got != 64<<10 {
		t.Fatalf("UploadPipeCap=%d want 64KiB (bulk-flush gate)", got)
	}
	wakeN := 0
	wrapped.(interface{ SetMasqueUploadFlowWake(func()) }).SetMasqueUploadFlowWake(func() { wakeN++ })
	if _, err := pw.Write([]byte("abcd")); err != nil {
		t.Fatal(err)
	}
	if wakeN != 1 {
		t.Fatalf("flow wake calls=%d want 1 (wrapper must forward SetMasqueUploadFlowWake)", wakeN)
	}
	if got := wrapped.(interface{ MasqueUploadBuffered() int }).MasqueUploadBuffered(); got != 4 {
		t.Fatalf("MasqueUploadBuffered=%d want 4", got)
	}
	buf := make([]byte, 8)
	n, err := wrapped.Read(buf)
	if err != nil || n != 4 {
		t.Fatalf("Read n=%d err=%v", n, err)
	}
}
