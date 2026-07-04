package h3

import (
	"testing"

	"github.com/quic-go/quic-go/http3"
)

func TestH3UploadChunkBytesProd(t *testing.T) {
	if got := H3UploadChunkBytes(false, false, false); got != TunnelWriteToBufLen {
		t.Fatalf("sequential upload chunk=%d want %d", got, TunnelWriteToBufLen)
	}
	for _, delivered := range []bool{false, true} {
		for _, duplex := range []bool{false, true} {
			if got := H3UploadChunkBytes(true, delivered, duplex); got != H3UploadFlushChunkBytes {
				t.Fatalf("duplex upload chunk=%d want %d (delivered=%v duplex=%v)",
					got, H3UploadFlushChunkBytes, delivered, duplex)
			}
		}
	}
}

func TestH3QuicConnectUploadChunkParity(t *testing.T) {
	got := H3UploadFlushChunkBytes
	if got != 64*1024 {
		t.Fatalf("h3 flush chunk=%d want %d", got, 64*1024)
	}
	if got != http3.ConnectUploadChunkBytes() {
		t.Fatalf("h3/http3 chunk parity: h3=%d http3=%d", got, http3.ConnectUploadChunkBytes())
	}
}
