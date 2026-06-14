package masque

import (
	"errors"
	"io"
)

// p6UploadLegCloser closes the upload CONNECT leg then the P6 QUIC transport and refills session warm pool.
type p6UploadLegCloser struct {
	conn    io.Closer
	closer  io.Closer
	release func()
}

func (c p6UploadLegCloser) Close() error {
	var err error
	if c.conn != nil {
		err = c.conn.Close()
	}
	if c.closer != nil {
		err = errors.Join(err, c.closer.Close())
	}
	if c.release != nil {
		c.release()
	}
	return err
}
