package relay

import (
	"errors"
	"io"
	"net"
	"time"

	"github.com/sagernet/sing-box/transport/masque/stream/conn"
)

// StripH3ClientBootstrapUpload removes one-shot H3 bidi bootstrap padding before relaying to onward TCP.
func StripH3ClientBootstrapUpload(r io.Reader) io.Reader {
	if r == nil {
		return nil
	}
	n := conn.H2BidiBootstrapUploadBytes()
	if n <= 0 {
		return r
	}
	return &h3BootstrapUploadStripper{inner: r, skip: n}
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
	useTimeout := false
	if d, ok := s.inner.(interface{ SetReadDeadline(time.Time) error }); ok {
		useTimeout = true
		_ = d.SetReadDeadline(time.Now().Add(3 * time.Millisecond))
		defer func() { _ = d.SetReadDeadline(time.Time{}) }()
	}
	for s.skip > 0 {
		n := s.skip
		if n > len(s.scratch) {
			n = len(s.scratch)
		}
		got, err := s.inner.Read(s.scratch[:n])
		if got == 0 {
			if useTimeout {
				var ne net.Error
				if errors.As(err, &ne) && ne.Timeout() {
					s.skip = 0
					return nil
				}
			}
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
