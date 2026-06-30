package h3

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestTunnelConnH3OnlyProdContract locks STR-4a1: prod TunnelConn is single *http3.Stream only;
// legacy pipe_upload reader/writer split lives in pipe_upload_conn.go.
func TestTunnelConnH3OnlyProdContract(t *testing.T) {
	t.Parallel()
	src := readH3Source(t, "tunnel_conn.go")
	for _, needle := range []string{
		"c.reader",
		"c.writer",
		"Reader       io.ReadCloser",
		"Writer       io.WriteCloser",
	} {
		if strings.Contains(src, needle) {
			t.Fatalf("tunnel_conn.go must not contain %q (pipe split → pipe_upload_conn.go)", needle)
		}
	}
	fromResp := readH3Source(t, "tunnel_from_response.go")
	if strings.Contains(fromResp, "Reader:") || strings.Contains(fromResp, "Writer:") {
		t.Fatal("tunnel_from_response must dial H3Stream only")
	}
	pipe := readH3Source(t, "pipe_upload_conn.go")
	if !strings.Contains(pipe, "PipeUploadTunnelConn") {
		t.Fatal("pipe_upload_conn.go must define PipeUploadTunnelConn")
	}
}

func readH3Source(t *testing.T, name string) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(wd, name)
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
