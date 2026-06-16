package stream

import (
	"io"
	"os"
	"strconv"
	"strings"
)

const envH3BidiBootstrapUpload = "MASQUE_H3_BIDI_BOOTSTRAP_UPLOAD_BYTES"

// StripH3ClientBootstrapUpload removes one-shot H3 bidi bootstrap padding (all-zero upload
// wake from client WriteTo) before relaying to onward TCP. Parity StripH2ClientBootstrapUpload.
func StripH3ClientBootstrapUpload(r io.Reader) io.Reader {
	if r == nil {
		return nil
	}
	n := h3BootstrapUploadBytes()
	if n <= 0 {
		return r
	}
	return &h3BootstrapUploadStripper{inner: r, skip: n}
}

func h3BootstrapUploadBytes() int {
	for _, key := range []string{envH3BidiBootstrapUpload, envH2BidiBootstrapUpload} {
		if n := parseH3BootstrapUploadBytes(os.Getenv(key)); n >= 0 {
			return n
		}
	}
	return H2BidiBootstrapUploadBytes()
}

func parseH3BootstrapUploadBytes(raw string) int {
	raw = strings.ToLower(strings.TrimSpace(raw))
	if raw == "" {
		return -1
	}
	if raw == "0" || raw == "false" || raw == "no" || raw == "off" {
		return 0
	}
	kb, err := strconv.Atoi(raw)
	if err != nil || kb <= 0 {
		return h2ConnectUploadChunkBytes()
	}
	if kb > 1024 {
		kb = 1024
	}
	return kb * 1024
}

type h3BootstrapUploadStripper struct {
	inner   io.Reader
	skip    int
	pending []byte
	scratch [512]byte
}

func (s *h3BootstrapUploadStripper) Read(p []byte) (int, error) {
	if s == nil || s.inner == nil {
		return 0, io.EOF
	}
	if len(s.pending) > 0 {
		n := copy(p, s.pending)
		s.pending = s.pending[n:]
		return n, nil
	}
	if s.skip > 0 {
		if err := s.discardBootstrapPrefix(); err != nil && len(s.pending) == 0 {
			return 0, err
		}
		if len(s.pending) > 0 {
			n := copy(p, s.pending)
			s.pending = s.pending[n:]
			return n, nil
		}
	}
	return s.inner.Read(p)
}

func (s *h3BootstrapUploadStripper) discardBootstrapPrefix() error {
	for s.skip > 0 {
		n := s.skip
		if n > len(s.scratch) {
			n = len(s.scratch)
		}
		got, err := s.inner.Read(s.scratch[:n])
		if got == 0 {
			return err
		}
		if !h2BootstrapUploadAllZero(s.scratch[:got]) {
			s.skip = 0
			s.pending = append(s.pending[:0], s.scratch[:got]...)
			return nil
		}
		if got > s.skip {
			got = s.skip
		}
		s.skip -= got
		if err != nil {
			return err
		}
	}
	return nil
}
