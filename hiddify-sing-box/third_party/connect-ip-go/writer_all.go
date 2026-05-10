package connectip

import (
	"errors"
	"io"
)

// writeAllWriter writes all of p to w per the io.Writer contract (partial writes without error).
func writeAllWriter(w io.Writer, p []byte) (int, error) {
	if w == nil {
		return 0, errors.New("connect-ip: nil writer")
	}
	nn := 0
	for nn < len(p) {
		n, err := w.Write(p[nn:])
		nn += n
		if err != nil {
			return nn, err
		}
		if n == 0 {
			return nn, io.ErrShortWrite
		}
	}
	return nn, nil
}
