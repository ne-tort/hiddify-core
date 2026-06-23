package masque

import (
	"testing"
	"time"

	"github.com/sagernet/sing-box/transport/masque/connectudp"
)

func TestConnectUDPUploadSmokeOneWrite(t *testing.T) {
	h := startConnectUDPProdH3UploadHandle(t)
	defer h.close()
	payload := make([]byte, connectudp.DefaultBenchUDPPayloadLen)
	_ = h.pkt.SetWriteDeadline(time.Now().Add(3 * time.Second))
	if _, err := h.pkt.WriteTo(payload, h.sinkAddr); err != nil {
		t.Fatalf("ListenPacket WriteTo: %v", err)
	}
}

func TestConnectUDPUploadSmokeBurst(t *testing.T) {
	h := startConnectUDPProdH3UploadHandle(t)
	defer h.close()
	payload := make([]byte, connectudp.DefaultBenchUDPPayloadLen)
	deadline := time.Now().Add(500 * time.Millisecond)
	var sent int
	for time.Now().Before(deadline) {
		_ = h.pkt.SetWriteDeadline(time.Now().Add(100 * time.Millisecond))
		if _, err := h.pkt.WriteTo(payload, h.sinkAddr); err != nil {
			t.Fatalf("WriteTo after %d packets: %v", sent, err)
		}
		sent++
	}
	t.Logf("upload smoke burst: %d packets in 500ms", sent)
}
