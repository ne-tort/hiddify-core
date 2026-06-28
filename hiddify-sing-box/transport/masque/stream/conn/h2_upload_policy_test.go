package conn

import "testing"

func TestH2UploadPolicyDefaultBulkPassthrough(t *testing.T) {
	t.Setenv(EnvH2ConnectUploadChunk, "")
	t.Setenv(EnvH2ConnectUploadBulkFlush, "1")
	p := CurrentH2UploadPolicy()
	if p.WrapChunkBytes() != 0 {
		t.Fatalf("wrap chunk: got %d want 0 (bulk passthrough)", p.WrapChunkBytes())
	}
	if p.ReadChunkBytes() != defaultH2ConnectUploadChunkBytes {
		t.Fatalf("read chunk: got %d want %d", p.ReadChunkBytes(), defaultH2ConnectUploadChunkBytes)
	}
	if !p.BulkFlushEnabled() {
		t.Fatal("bulk flush should be enabled by default")
	}
}

func TestH2UploadPolicyFromEnv(t *testing.T) {
	tests := []struct {
		env      string
		bulk     string
		wantWrap int
		wantRead int
	}{
		{"", "1", 0, defaultH2ConnectUploadChunkBytes},
		{"4", "1", 4 * 1024, 4 * 1024},
		{"8", "1", 8 * 1024, 8 * 1024},
		{"0", "1", 0, defaultH2ConnectUploadChunkBytes},
		{"-1", "1", 0, defaultH2ConnectUploadChunkBytes},
		{"bogus", "1", 0, defaultH2ConnectUploadChunkBytes},
		{"2048", "1", 1024 * 1024, 1024 * 1024},
		{"", "0", defaultH2ConnectUploadChunkBytes, defaultH2ConnectUploadChunkBytes},
		{"4", "0", 4 * 1024, 4 * 1024},
	}
	for _, tc := range tests {
		name := tc.env
		if name == "" {
			name = "default"
		}
		t.Run(name, func(t *testing.T) {
			t.Setenv(EnvH2ConnectUploadChunk, tc.env)
			t.Setenv(EnvH2ConnectUploadBulkFlush, tc.bulk)
			p := CurrentH2UploadPolicy()
			if p.WrapChunkBytes() != tc.wantWrap {
				t.Fatalf("wrap: got %d want %d", p.WrapChunkBytes(), tc.wantWrap)
			}
			if p.ReadChunkBytes() != tc.wantRead {
				t.Fatalf("read: got %d want %d", p.ReadChunkBytes(), tc.wantRead)
			}
		})
	}
}

func TestH2ConnectUploadChunkBytesDelegatesPolicy(t *testing.T) {
	t.Setenv(EnvH2ConnectUploadChunk, "4")
	t.Setenv(EnvH2ConnectUploadBulkFlush, "1")
	if got := H2ConnectUploadChunkBytes(); got != 4*1024 {
		t.Fatalf("got %d want %d", got, 4*1024)
	}
}
