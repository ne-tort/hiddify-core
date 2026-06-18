package stream

import (
	"io"
	"strings"
	"testing"
	"time"
)

func TestRelayH3ProbeConcurrentUploadEOF(t *testing.T) {
	t.Parallel()
	src, expects := relayH3ProbeConcurrentUpload(strings.NewReader(""))
	if expects {
		t.Fatal("immediate EOF upload leg must not expect saturated duplex")
	}
	if src == nil {
		t.Fatal("probe must return reader")
	}
}

func TestRelayH3ProbeConcurrentUploadTimeout(t *testing.T) {
	t.Parallel()
	r := timeoutReader{}
	src, expects := relayH3ProbeConcurrentUpload(r)
	if expects {
		t.Fatal("upload read timeout with no bytes must be download-primary (iperf -R)")
	}
	if src != r {
		t.Fatal("probe must return same reader on timeout")
	}
}

type timeoutReader struct{}

func (timeoutReader) Read([]byte) (int, error) { return 0, &timeoutError{} }
func (timeoutReader) SetReadDeadline(time.Time) error { return nil }

type timeoutError struct{}

func (timeoutError) Error() string   { return "timeout" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return true }

func TestRelayH3ProbeConcurrentUploadHasByte(t *testing.T) {
	t.Parallel()
	src, expects := relayH3ProbeConcurrentUpload(strings.NewReader("x"))
	if expects {
		t.Fatal("small upload peek must not arm saturated duplex at probe")
	}
	b, err := io.ReadAll(src)
	if err != nil {
		t.Fatalf("read probed upload: %v", err)
	}
	if string(b) != "x" {
		t.Fatalf("probe consumed byte: %q", b)
	}
}

func TestRelayH3ProbeConcurrentUploadBulk(t *testing.T) {
	t.Parallel()
	bulk := strings.Repeat("a", relayDuplexArmUploadBytes)
	src, expects := relayH3ProbeConcurrentUpload(strings.NewReader(bulk))
	if !expects {
		t.Fatal("bulk upload peek must arm saturated duplex at probe")
	}
	if _, err := io.Copy(io.Discard, src); err != nil {
		t.Fatalf("drain probed bulk: %v", err)
	}
}
