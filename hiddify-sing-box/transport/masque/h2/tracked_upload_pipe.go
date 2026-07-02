package h2

import (
	"io"
	"sync/atomic"
)

// trackedPipeReader wraps io.PipeReader with MasqueUploadWriterOpen (connect-ip-go bidi parity).
type trackedPipeReader struct {
	io.ReadCloser
	writerOpen *atomic.Bool
}

func (r *trackedPipeReader) MasqueUploadWriterOpen() bool {
	if r == nil || r.writerOpen == nil {
		return false
	}
	return r.writerOpen.Load()
}

type trackedPipeWriter struct {
	io.WriteCloser
	writerOpen *atomic.Bool
}

func (w *trackedPipeWriter) Close() error {
	if w != nil && w.writerOpen != nil {
		w.writerOpen.Store(false)
	}
	if w == nil || w.WriteCloser == nil {
		return nil
	}
	return w.WriteCloser.Close()
}

// NewTrackedUploadPipe is Invisv io.Pipe + writer-open discriminator for http2 END_STREAM deferral.
func NewTrackedUploadPipe() (io.ReadCloser, ConnectUploadPipeWriter) {
	pr, pw := io.Pipe()
	open := atomic.Bool{}
	open.Store(true)
	r := &trackedPipeReader{ReadCloser: pr, writerOpen: &open}
	w := &trackedPipeWriter{WriteCloser: pw, writerOpen: &open}
	return r, &trackedPipeWriterTracked{trackedPipeWriter: w}
}

// trackedPipeWriterTracked adds MasqueUploadWriterOpen for ExtendedConnectUploadBody.Writer.
type trackedPipeWriterTracked struct{ *trackedPipeWriter }

func (w *trackedPipeWriterTracked) MasqueUploadWriterOpen() bool {
	if w == nil || w.trackedPipeWriter == nil {
		return false
	}
	return w.trackedPipeWriter.writerOpen != nil && w.trackedPipeWriter.writerOpen.Load()
}
