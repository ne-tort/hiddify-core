package h3

import (
	"testing"

	"github.com/quic-go/quic-go/http3"
)

// TestH3UploadChunkBytesLeg (H3-T1b-01) — upload-primary uses 64 KiB; true duplex uses env/default.
func TestH3UploadChunkBytesLeg(t *testing.T) {
	if got := H3UploadChunkBytes(false, false, false); got != tunnelWriteToBufLen {
		t.Fatalf("upload-primary chunk=%d want %d", got, tunnelWriteToBufLen)
	}
	if got := H3UploadChunkBytes(true, false, false); got != tunnelWriteToBufLen {
		t.Fatalf("download-active idle chunk=%d want %d", got, tunnelWriteToBufLen)
	}
	if got := H3UploadChunkBytes(true, false, true); got != defaultDuplexUploadChunkBytes {
		t.Fatalf("duplex bootstrap chunk=%d want %d", got, defaultDuplexUploadChunkBytes)
	}
	if got := H3UploadChunkBytes(true, true, false); got != defaultDuplexUploadChunkBytes {
		t.Fatalf("download-delivered bootstrap chunk=%d want %d", got, defaultDuplexUploadChunkBytes)
	}
	if got := H3UploadChunkBytes(true, true, true); got != tunnelWriteToBufLen {
		t.Fatalf("steady concurrent duplex chunk=%d want %d", got, tunnelWriteToBufLen)
	}
}

// TestH3QuicConnectUploadChunkParity (S62): TunnelConn upload chunking must match
// quic-go http3 CONNECT request-body copy size for the same env knobs.
func TestH3QuicConnectUploadChunkParity(t *testing.T) {
	cases := []struct {
		h3   string
		h2   string
		want int
	}{
		{"", "", defaultUploadChunkBytes},
		{"8", "", 8 * 1024},
		{"", "4", 4 * 1024},
		{"0", "4", 4 * 1024},
		{"bogus", "", defaultUploadChunkBytes},
		{"2048", "", 1024 * 1024},
	}
	for _, tc := range cases {
		t.Run(tc.h3+"/"+tc.h2, func(t *testing.T) {
			t.Setenv(envH3UploadChunkKB, tc.h3)
			t.Setenv(envH2UploadChunkKB, tc.h2)

			got := H3UploadFlushPolicy().ChunkBytes
			if got != tc.want {
				t.Fatalf("h3 policy chunk=%d want %d", got, tc.want)
			}
			if got != http3.ConnectUploadChunkBytes() {
				t.Fatalf("h3/http3 chunk parity: h3=%d http3=%d", got, http3.ConnectUploadChunkBytes())
			}
		})
	}
}
