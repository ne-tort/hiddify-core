package session

import (
	"context"
	"sync"

	"github.com/quic-go/quic-go/http3"
)

// p6UploadWarmPool holds one pre-warmed ephemeral CONNECT-stream transport between P6 upload legs.
// Refill runs only after a prior leg closes — never during an active route copy (H3-L1c-5).
type p6UploadWarmPool struct {
	mu      sync.Mutex
	ready   *http3.Transport
	warming bool
}

// KickP6UploadWarmPoolIdle starts background QUIC handshake when the pool slot is empty.
// Call after P6 upload leg close or before first P6 dial — not during active duplex copy.
func KickP6UploadWarmPoolIdle(ctx context.Context, s *CoreSession) {
	if s == nil || ctx == nil || ctx.Err() != nil {
		return
	}
	s.p6UploadWarm.kick(ctx, s)
}

// AcquireP6UploadTransport returns a warmed ephemeral transport or completes sync warm on miss.
func AcquireP6UploadTransport(ctx context.Context, s *CoreSession) (*http3.Transport, error) {
	if s == nil {
		return nil, context.Canceled
	}
	return s.p6UploadWarm.acquire(ctx, s)
}

func (p *p6UploadWarmPool) kick(ctx context.Context, s *CoreSession) {
	if p == nil || s == nil {
		return
	}
	p.mu.Lock()
	if p.ready != nil || p.warming {
		p.mu.Unlock()
		return
	}
	p.warming = true
	p.mu.Unlock()

	go func() {
		tr := NewTCPConnectStreamHTTP3Transport(s)
		warmErr := WarmTCPConnectStreamHTTP3Transport(ctx, s, tr)

		p.mu.Lock()
		defer p.mu.Unlock()
		p.warming = false
		if warmErr != nil {
			if tr != nil {
				_ = tr.Close()
			}
			return
		}
		if p.ready != nil {
			_ = tr.Close()
			return
		}
		p.ready = tr
	}()
}

func (p *p6UploadWarmPool) acquire(ctx context.Context, s *CoreSession) (*http3.Transport, error) {
	if p == nil {
		tr := NewTCPConnectStreamHTTP3Transport(s)
		if err := WarmTCPConnectStreamHTTP3Transport(ctx, s, tr); err != nil {
			_ = tr.Close()
			return nil, err
		}
		return tr, nil
	}

	p.mu.Lock()
	if tr := p.ready; tr != nil {
		p.ready = nil
		p.mu.Unlock()
		return tr, nil
	}
	p.mu.Unlock()

	tr := NewTCPConnectStreamHTTP3Transport(s)
	if err := WarmTCPConnectStreamHTTP3Transport(ctx, s, tr); err != nil {
		_ = tr.Close()
		return nil, err
	}
	return tr, nil
}
