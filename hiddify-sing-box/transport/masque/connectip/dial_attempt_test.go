package connectip

import (
	"context"
	"errors"
	"testing"

	cip "github.com/quic-go/connect-ip-go"
	"github.com/quic-go/quic-go/http3"
)

type dialAttemptFakeHost struct {
	hook              func(ctx context.Context, useHTTP2 bool) (*cip.Conn, error)
	onSuccess         int
	onCtxCanceled     int
	dialH2            func(ctx context.Context) (*cip.Conn, error)
	hasTemplateIP     bool
	errNoTemplateIP   error
	logH3Attempt      []string
	openH3            func(ctx context.Context) (*http3.ClientConn, error)
	dialH3            func(ctx context.Context, cc *http3.ClientConn) (*cip.Conn, error)
	overlayDialAddr   string
	lastSuccessH2     *bool
}

func (h *dialAttemptFakeHost) Hook() func(ctx context.Context, useHTTP2 bool) (*cip.Conn, error) {
	return h.hook
}

func (h *dialAttemptFakeHost) OnSuccess(useHTTP2 bool) {
	h.onSuccess++
	v := useHTTP2
	h.lastSuccessH2 = &v
}

func (h *dialAttemptFakeHost) OnCtxCanceled() {
	h.onCtxCanceled++
}

func (h *dialAttemptFakeHost) DialH2(ctx context.Context) (*cip.Conn, error) {
	if h.dialH2 == nil {
		return &cip.Conn{}, nil
	}
	return h.dialH2(ctx)
}

func (h *dialAttemptFakeHost) HasTemplateIP() bool {
	return h.hasTemplateIP
}

func (h *dialAttemptFakeHost) ErrNoTemplateIP() error {
	if h.errNoTemplateIP != nil {
		return h.errNoTemplateIP
	}
	return errors.New("no template")
}

func (h *dialAttemptFakeHost) LogH3Attempt(dialAddr string) {
	h.logH3Attempt = append(h.logH3Attempt, dialAddr)
}

func (h *dialAttemptFakeHost) OpenH3ClientConn(ctx context.Context) (*http3.ClientConn, error) {
	if h.openH3 == nil {
		return &http3.ClientConn{}, nil
	}
	return h.openH3(ctx)
}

func (h *dialAttemptFakeHost) DialH3WithBootstrap(ctx context.Context, clientConn *http3.ClientConn) (*cip.Conn, error) {
	if h.dialH3 == nil {
		return &cip.Conn{}, nil
	}
	return h.dialH3(ctx, clientConn)
}

func (h *dialAttemptFakeHost) OverlayDialAddr() string {
	return h.overlayDialAddr
}

func TestDialAttemptHookSuccessRecordsLayer(t *testing.T) {
	host := &dialAttemptFakeHost{
		hook: func(_ context.Context, useHTTP2 bool) (*cip.Conn, error) {
			if useHTTP2 {
				return &cip.Conn{}, nil
			}
			return nil, errors.New("h3 hook fail")
		},
	}
	conn, err := DialAttempt(context.Background(), host, true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if conn == nil {
		t.Fatal("expected conn")
	}
	if host.onSuccess != 1 {
		t.Fatalf("onSuccess=%d want 1", host.onSuccess)
	}
	if host.lastSuccessH2 == nil || !*host.lastSuccessH2 {
		t.Fatal("expected H2 success recorded")
	}
}

func TestDialAttemptHookErrorSkipsSuccess(t *testing.T) {
	wantErr := errors.New("hook fail")
	host := &dialAttemptFakeHost{
		hook: func(context.Context, bool) (*cip.Conn, error) {
			return nil, wantErr
		},
	}
	_, err := DialAttempt(context.Background(), host, false)
	if !errors.Is(err, wantErr) {
		t.Fatalf("expected hook error, got %v", err)
	}
	if host.onSuccess != 0 {
		t.Fatalf("onSuccess=%d want 0", host.onSuccess)
	}
}

func TestDialAttemptH2CanceledClearsFallbackLatch(t *testing.T) {
	host := &dialAttemptFakeHost{
		dialH2: func(context.Context) (*cip.Conn, error) {
			t.Fatal("DialH2 must not run when ctx already canceled")
			return nil, nil
		},
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := DialAttempt(ctx, host, true)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
	if host.onCtxCanceled != 1 {
		t.Fatalf("onCtxCanceled=%d want 1", host.onCtxCanceled)
	}
}

func TestDialAttemptH3CanceledClearsFallbackLatch(t *testing.T) {
	host := &dialAttemptFakeHost{
		hasTemplateIP:     true,
		overlayDialAddr:   "127.0.0.1:443",
		openH3: func(context.Context) (*http3.ClientConn, error) {
			t.Fatal("OpenH3ClientConn must not run when ctx already canceled")
			return nil, nil
		},
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := DialAttempt(ctx, host, false)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
	if host.onCtxCanceled != 1 {
		t.Fatalf("onCtxCanceled=%d want 1", host.onCtxCanceled)
	}
}

func TestDialAttemptH3MissingTemplate(t *testing.T) {
	wantErr := errors.New("template missing")
	host := &dialAttemptFakeHost{
		hasTemplateIP:   false,
		errNoTemplateIP: wantErr,
	}
	_, err := DialAttempt(context.Background(), host, false)
	if !errors.Is(err, wantErr) {
		t.Fatalf("expected template error, got %v", err)
	}
}

func TestDialAttemptH3SuccessPath(t *testing.T) {
	host := &dialAttemptFakeHost{
		hasTemplateIP:     true,
		overlayDialAddr:   "example.com:443",
		openH3:            func(context.Context) (*http3.ClientConn, error) { return &http3.ClientConn{}, nil },
		dialH3:            func(context.Context, *http3.ClientConn) (*cip.Conn, error) { return &cip.Conn{}, nil },
	}
	conn, err := DialAttempt(context.Background(), host, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if conn == nil {
		t.Fatal("expected conn")
	}
	if len(host.logH3Attempt) != 1 || host.logH3Attempt[0] != "example.com:443" {
		t.Fatalf("logH3Attempt=%v", host.logH3Attempt)
	}
	if host.onSuccess != 1 || host.lastSuccessH2 == nil || *host.lastSuccessH2 {
		t.Fatal("expected H3 success recorded")
	}
}
