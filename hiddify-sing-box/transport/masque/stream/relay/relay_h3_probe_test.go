package relay

import (
	"bytes"
	"io"
	"testing"
)

func TestRelayH3ProbeUploadLegBootstrapZeroNotUploadStarted(t *testing.T) {
	t.Parallel()
	src := bytes.NewReader([]byte{0})
	r, mode, uploadStarted := relayH3ProbeUploadLeg(src)
	if mode != relayH3UploadLegNeutral {
		t.Fatalf("mode=%v want neutral", mode)
	}
	if uploadStarted {
		t.Fatal("all-zero bootstrap byte must not mark upload started")
	}
	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("read probed: %v", err)
	}
	if !bytes.Equal(out, []byte{0}) {
		t.Fatalf("probed prefix lost: %q", out)
	}
}

func TestRelayH3ProbeUploadLegPayloadMarksUploadStarted(t *testing.T) {
	t.Parallel()
	payload := []byte("FAKEIPERF")
	src := bytes.NewReader(payload)
	r, mode, uploadStarted := relayH3ProbeUploadLeg(src)
	if mode != relayH3UploadLegNeutral {
		t.Fatalf("mode=%v want neutral", mode)
	}
	if !uploadStarted {
		t.Fatal("non-bootstrap first byte must mark upload started")
	}
	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("read probed: %v", err)
	}
	if !bytes.Equal(out, payload) {
		t.Fatalf("probed prefix lost: %q", out)
	}
}

