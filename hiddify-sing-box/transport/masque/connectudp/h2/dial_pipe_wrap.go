package h2

import "io"

// connectUDPNoXNetBulkPipe reports ≤64KiB UploadPipeCap so x/net masque_upload_bulk_flush
// stays off CONNECT-UDP (REF-H2-02), while still forwarding pipe depth / flow-wake to the
// real shallow upload pipe. A bare io.ReadCloser wrap previously hid MasqueUploadBuffered
// and SetMasqueUploadFlowWake — http2 saw buffered=0 always and never installed FC wake.
type connectUDPNoXNetBulkPipe struct {
	inner io.ReadCloser
}

func wrapConnectUDPNoXNetBulkPipe(r io.ReadCloser) io.ReadCloser {
	if r == nil {
		return nil
	}
	return connectUDPNoXNetBulkPipe{inner: r}
}

func (p connectUDPNoXNetBulkPipe) Read(b []byte) (int, error) { return p.inner.Read(b) }
func (p connectUDPNoXNetBulkPipe) Close() error               { return p.inner.Close() }

// UploadPipeCap forces the no-bulk-flush gate (≤64KiB) regardless of real pipe capacity.
func (connectUDPNoXNetBulkPipe) UploadPipeCap() int { return 64 << 10 }

func (p connectUDPNoXNetBulkPipe) MasqueUploadBuffered() int {
	if u, ok := p.inner.(interface{ MasqueUploadBuffered() int }); ok {
		return u.MasqueUploadBuffered()
	}
	return 0
}

func (p connectUDPNoXNetBulkPipe) MasqueUploadWriterOpen() bool {
	if u, ok := p.inner.(interface{ MasqueUploadWriterOpen() bool }); ok {
		return u.MasqueUploadWriterOpen()
	}
	return false
}

func (p connectUDPNoXNetBulkPipe) SetMasqueUploadFlowWake(fn func()) {
	if u, ok := p.inner.(interface{ SetMasqueUploadFlowWake(func()) }); ok {
		u.SetMasqueUploadFlowWake(fn)
	}
}

func (p connectUDPNoXNetBulkPipe) MasqueWakeUploadFlow() {
	if u, ok := p.inner.(interface{ MasqueWakeUploadFlow() }); ok {
		u.MasqueWakeUploadFlow()
	}
}
