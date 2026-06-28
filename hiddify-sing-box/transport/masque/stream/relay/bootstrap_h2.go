package relay

import (
	"bytes"
	"io"

	"github.com/sagernet/sing-box/transport/masque/stream/conn"
)

// StripH2ClientBootstrapUpload removes one-shot H2 bidi bootstrap padding (all-zero upload
// wake from client WriteTo) before relaying to onward TCP.
func StripH2ClientBootstrapUpload(reqBody io.ReadCloser) io.Reader {
	if reqBody == nil {
		return nil
	}
	n := conn.H2BidiBootstrapUploadBytes()
	if n <= 0 {
		return reqBody
	}
	return &h2BootstrapUploadStripper{inner: reqBody, skip: n}
}

type h2BootstrapUploadStripper struct {
	inner   io.ReadCloser
	skip    int
	pending []byte
	scratch [512]byte
}

func (s *h2BootstrapUploadStripper) Read(p []byte) (int, error) {
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

func (s *h2BootstrapUploadStripper) discardBootstrapPrefix() error {
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

func (s *h2BootstrapUploadStripper) Close() error {
	if s == nil || s.inner == nil {
		return nil
	}
	return s.inner.Close()
}

func h2BootstrapUploadAllZero(b []byte) bool {
	for _, c := range b {
		if c != 0 {
			return false
		}
	}
	return len(b) > 0
}

// ReplayH2BootstrapUpload prepends bytes for tests simulating stripper replay path.
func ReplayH2BootstrapUpload(head []byte, rest io.Reader) io.Reader {
	if len(head) == 0 {
		return rest
	}
	return io.MultiReader(bytes.NewReader(head), rest)
}
