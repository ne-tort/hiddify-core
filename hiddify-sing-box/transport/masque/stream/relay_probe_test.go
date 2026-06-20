package stream

import (
	"io"
	"strings"
	"testing"
	"time"
)

type deadlineReader struct {
	r io.Reader
}

func (d *deadlineReader) Read(p []byte) (int, error) { return d.r.Read(p) }
func (d *deadlineReader) SetReadDeadline(time.Time) error { return nil }

func TestRelayH3ProbeUploadLegEOF(t *testing.T) {
	t.Parallel()
	src, mode := relayH3ProbeUploadLeg(strings.NewReader(""))
	if mode != relayH3UploadLegDownloadPrimary {
		t.Fatalf("immediate EOF: mode=%v want download-primary", mode)
	}
	if src == nil {
		t.Fatal("probe must return reader")
	}
}

func TestRelayH3ProbeUploadLegTimeoutNeutral(t *testing.T) {
	t.Parallel()
	r := timeoutReader{}
	src, mode := relayH3ProbeUploadLeg(r)
	if mode != relayH3UploadLegNeutral {
		t.Fatalf("upload read timeout with no bytes: mode=%v want neutral (not download-primary)", mode)
	}
	if src != r {
		t.Fatal("probe must return same reader on timeout")
	}
}

func TestRelayH3ProbeUploadLegSmallByteNeutral(t *testing.T) {
	t.Parallel()
	src, mode := relayH3ProbeUploadLeg(&deadlineReader{r: strings.NewReader("x")})
	if mode != relayH3UploadLegNeutral {
		t.Fatalf("small upload peek: mode=%v want neutral", mode)
	}
	b, err := io.ReadAll(src)
	if err != nil {
		t.Fatalf("read probed upload: %v", err)
	}
	if string(b) != "x" {
		t.Fatalf("probe consumed byte: %q", b)
	}
}

// TestLocalizeH3RelayProbeNeutralOnDeferredUpload documents synth duplex: client defers upload
// until download arms — server probe timeout must not classify as iperf -R download-primary.
func TestLocalizeH3RelayProbeNeutralOnDeferredUpload(t *testing.T) {
	t.Parallel()
	r := &deferredUploadReader{delay: 50 * time.Millisecond}
	src, mode := relayH3ProbeUploadLeg(r)
	if mode != relayH3UploadLegNeutral {
		t.Fatalf("deferred upload (probe timeout): mode=%v want neutral; download-primary misclass causes ~91 Mbps upload pole", mode)
	}
	if src == nil {
		t.Fatal("probe must return reader")
	}
}

type timeoutReader struct{}

func (timeoutReader) Read([]byte) (int, error) { return 0, &timeoutError{} }
func (timeoutReader) SetReadDeadline(time.Time) error { return nil }

type timeoutError struct{}

func (timeoutError) Error() string   { return "timeout" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return true }

type deferredUploadReader struct {
	delay time.Duration
}

func (d *deferredUploadReader) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	time.Sleep(d.delay)
	return copy(p, []byte("x")), nil
}

func (d *deferredUploadReader) SetReadDeadline(t time.Time) error { return nil }
