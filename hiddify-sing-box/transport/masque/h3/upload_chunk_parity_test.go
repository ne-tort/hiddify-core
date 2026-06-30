package h3

import (
	"testing"

	"github.com/quic-go/quic-go/http3"
)

func TestH3UploadChunkBytesProd(t *testing.T) {
	for _, active := range []bool{false, true} {
		for _, delivered := range []bool{false, true} {
			for _, duplex := range []bool{false, true} {
				if got := H3UploadChunkBytes(active, delivered, duplex); got != TunnelWriteToBufLen {
					t.Fatalf("chunk=%d want %d (active=%v delivered=%v duplex=%v)",
						got, TunnelWriteToBufLen, active, delivered, duplex)
				}
			}
		}
	}
}

func TestH3QuicConnectUploadChunkParity(t *testing.T) {
	got := H3UploadFlushPolicy().ChunkBytes
	if got != defaultUploadChunkBytes {
		t.Fatalf("h3 policy chunk=%d want %d", got, defaultUploadChunkBytes)
	}
	if got != http3.ConnectUploadChunkBytes() {
		t.Fatalf("h3/http3 chunk parity: h3=%d http3=%d", got, http3.ConnectUploadChunkBytes())
	}
}
